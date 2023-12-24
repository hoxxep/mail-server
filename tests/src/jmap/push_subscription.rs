/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::{engine::general_purpose, Engine};
use ece::EcKeyComponents;

use hyper::{body, server::conn::http1, service::service_fn, StatusCode};
use hyper_util::rt::TokioIo;
use jmap::{
    api::{
        http::{fetch_body, ToHttpResponse},
        HtmlResponse, StateChangeResponse,
    },
    auth::AccessToken,
    push::ece::ece_encrypt,
    JMAP,
};
use jmap_client::{client::Client, mailbox::Role, push_subscription::Keys};
use jmap_proto::types::{id::Id, type_state::DataType};
use reqwest::header::CONTENT_ENCODING;
use store::ahash::AHashSet;
use tokio::{net::TcpStream, sync::mpsc};
use utils::listener::SessionData;

use crate::{
    add_test_certs,
    directory::sql::create_test_user_with_email,
    jmap::{mailbox::destroy_all_mailboxes, test_account_login},
};

const SERVER: &str = "
[server]
hostname = 'jmap-push.example.org'

[server.listener.jmap]
bind = ['127.0.0.1:9000']
url = 'https://127.0.0.1:9000'
protocol = 'jmap'

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = 'default'

[certificate.default]
cert = 'file://{CERT}'
private-key = 'file://{PK}'
";

pub async fn test(server: Arc<JMAP>, admin_client: &mut Client) {
    println!("Running Push Subscription tests...");

    // Create test account
    let directory = server.directory.as_ref();
    create_test_user_with_email(directory, "jdoe@example.com", "12345", "John Doe").await;
    let account_id = Id::from(server.get_account_id("jdoe@example.com").await.unwrap());
    admin_client.set_default_account_id(account_id);
    let client = test_account_login("jdoe@example.com", "12345").await;

    // Create channels
    let (event_tx, mut event_rx) = mpsc::channel::<PushMessage>(100);

    // Create subscription keys
    let (keypair, auth_secret) = ece::generate_keypair_and_auth_secret().unwrap();
    let pubkey = keypair.pub_as_raw().unwrap();
    let keys = Keys::new(&pubkey, &auth_secret);

    let push_server = Arc::new(PushServer {
        keypair: keypair.raw_components().unwrap(),
        auth_secret: auth_secret.to_vec(),
        tx: event_tx,
        fail_requests: false.into(),
    });

    // Start mock push server
    let settings = utils::config::Config::new(&add_test_certs(SERVER)).unwrap();
    let servers = settings.parse_servers().unwrap();

    // Start JMAP server
    let manager = SessionManager::from(push_server.clone());
    servers.bind(&settings);
    let _shutdown_tx = servers.spawn(|server, shutdown_rx| {
        server.spawn(manager.clone(), shutdown_rx);
    });

    // Register push notification (no encryption)
    let push_id = client
        .push_subscription_create("123", "https://127.0.0.1:9000/push", None)
        .await
        .unwrap()
        .take_id();

    // Expect push verification
    let verification = expect_push(&mut event_rx).await.unwrap_verification();
    assert_eq!(verification.push_subscription_id, push_id);

    // Update verification code
    client
        .push_subscription_verify(&push_id, verification.verification_code)
        .await
        .unwrap();

    // Create a mailbox and expect a state change
    let mailbox_id = client
        .mailbox_create("PushSubscription Test", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    assert_state(&mut event_rx, &account_id, &[DataType::Mailbox]).await;

    // Receive states just for the requested types
    client
        .push_subscription_update_types(&push_id, [jmap_client::TypeState::Email].into())
        .await
        .unwrap();
    client
        .mailbox_update_sort_order(&mailbox_id, 123)
        .await
        .unwrap();
    expect_nothing(&mut event_rx).await;

    // Destroy subscription
    client.push_subscription_destroy(&push_id).await.unwrap();

    // Only one verification per minute is allowed
    let push_id = client
        .push_subscription_create("invalid", "https://127.0.0.1:9000/push", None)
        .await
        .unwrap()
        .take_id();
    expect_nothing(&mut event_rx).await;
    client.push_subscription_destroy(&push_id).await.unwrap();

    // Register push notification (with encryption)
    let push_id = client
        .push_subscription_create(
            "123",
            "https://127.0.0.1:9000/push?skip_checks=true", // skip_checks only works in cfg(test)
            keys.into(),
        )
        .await
        .unwrap()
        .take_id();

    // Expect push verification
    let verification = expect_push(&mut event_rx).await.unwrap_verification();
    assert_eq!(verification.push_subscription_id, push_id);

    // Update verification code
    client
        .push_subscription_verify(&push_id, verification.verification_code)
        .await
        .unwrap();

    // Failed deliveries should be re-attempted
    push_server.fail_requests.store(true, Ordering::Relaxed);
    client
        .mailbox_update_sort_order(&mailbox_id, 101)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    push_server.fail_requests.store(false, Ordering::Relaxed);
    assert_state(&mut event_rx, &account_id, &[DataType::Mailbox]).await;

    // Make a mailbox change and expect state change
    client
        .mailbox_rename(&mailbox_id, "My Mailbox")
        .await
        .unwrap();
    assert_state(&mut event_rx, &account_id, &[DataType::Mailbox]).await;
    //expect_nothing(&mut event_rx).await;

    // Multiple change updates should be grouped and pushed in intervals
    for num in 0..5 {
        client
            .mailbox_update_sort_order(&mailbox_id, num)
            .await
            .unwrap();
    }
    assert_state(&mut event_rx, &account_id, &[DataType::Mailbox]).await;
    expect_nothing(&mut event_rx).await;

    // Destroy mailbox
    client.push_subscription_destroy(&push_id).await.unwrap();
    client.mailbox_destroy(&mailbox_id, true).await.unwrap();
    expect_nothing(&mut event_rx).await;

    destroy_all_mailboxes(admin_client).await;

    server.store.assert_is_empty().await;
}

#[derive(Clone)]
pub struct SessionManager {
    pub inner: Arc<PushServer>,
}

impl From<Arc<PushServer>> for SessionManager {
    fn from(inner: Arc<PushServer>) -> Self {
        SessionManager { inner }
    }
}
pub struct PushServer {
    keypair: EcKeyComponents,
    auth_secret: Vec<u8>,
    tx: mpsc::Sender<PushMessage>,
    fail_requests: AtomicBool,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
enum PushMessage {
    StateChange(StateChangeResponse),
    Verification(PushVerification),
}

impl PushMessage {
    pub fn unwrap_state_change(self) -> StateChangeResponse {
        match self {
            PushMessage::StateChange(state_change) => state_change,
            _ => panic!("Expected StateChange"),
        }
    }

    pub fn unwrap_verification(self) -> PushVerification {
        match self {
            PushMessage::Verification(verification) => verification,
            _ => panic!("Expected Verification"),
        }
    }
}

#[derive(serde::Deserialize, Debug)]
enum PushVerificationType {
    PushVerification,
}

#[derive(serde::Deserialize, Debug)]
struct PushVerification {
    #[serde(rename = "@type")]
    _type: PushVerificationType,
    #[serde(rename = "pushSubscriptionId")]
    pub push_subscription_id: String,
    #[serde(rename = "verificationCode")]
    pub verification_code: String,
}

impl utils::listener::SessionManager for SessionManager {
    fn spawn(&self, session: SessionData<TcpStream>) {
        let push = self.inner.clone();

        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(
                        session
                            .instance
                            .tls_acceptor
                            .as_ref()
                            .unwrap()
                            .accept(session.stream)
                            .await
                            .unwrap(),
                    ),
                    service_fn(|mut req: hyper::Request<body::Incoming>| {
                        let push = push.clone();

                        async move {
                            if push.fail_requests.load(Ordering::Relaxed) {
                                return Ok(HtmlResponse::with_status(
                                    StatusCode::TOO_MANY_REQUESTS,
                                    "too many requests".to_string(),
                                )
                                .into_http_response());
                            }
                            let is_encrypted = req
                                .headers()
                                .get(CONTENT_ENCODING.as_str())
                                .map_or(false, |encoding| {
                                    encoding.to_str().unwrap() == "aes128gcm"
                                });
                            let body = fetch_body(&mut req, 1024 * 1024, &AccessToken::default())
                                .await
                                .unwrap();
                            let message = serde_json::from_slice::<PushMessage>(&if is_encrypted {
                                ece::decrypt(
                                    &push.keypair,
                                    &push.auth_secret,
                                    &general_purpose::URL_SAFE.decode(body).unwrap(),
                                )
                                .unwrap()
                            } else {
                                body
                            })
                            .unwrap();

                            //println!("Push received ({}): {:?}", is_encrypted, message);

                            push.tx.send(message).await.unwrap();

                            Ok::<_, hyper::Error>(
                                HtmlResponse::new("ok".to_string()).into_http_response(),
                            )
                        }
                    }),
                )
                .await;
        });
    }

    fn shutdown(&self) {}
}

async fn expect_push(event_rx: &mut mpsc::Receiver<PushMessage>) -> PushMessage {
    match tokio::time::timeout(Duration::from_millis(1500), event_rx.recv()).await {
        Ok(Some(push)) => {
            //println!("Push received: {:?}", push);
            push
        }
        result => {
            panic!("Timeout waiting for push: {:?}", result);
        }
    }
}

async fn expect_nothing(event_rx: &mut mpsc::Receiver<PushMessage>) {
    match tokio::time::timeout(Duration::from_millis(1000), event_rx.recv()).await {
        Err(_) => {}
        message => {
            panic!("Received a message when expecting nothing: {:?}", message);
        }
    }
}

async fn assert_state(event_rx: &mut mpsc::Receiver<PushMessage>, id: &Id, state: &[DataType]) {
    assert_eq!(
        expect_push(event_rx)
            .await
            .unwrap_state_change()
            .changed
            .get(id)
            .unwrap()
            .iter()
            .map(|x| x.0)
            .collect::<AHashSet<&DataType>>(),
        state.iter().collect::<AHashSet<&DataType>>()
    );
}

#[test]
fn ece_roundtrip() {
    for len in [1, 2, 5, 16, 256, 1024, 2048, 4096, 1024 * 1024] {
        let (keypair, auth_secret) = ece::generate_keypair_and_auth_secret().unwrap();

        let bytes: Vec<u8> = (0..len).map(|_| store::rand::random::<u8>()).collect();

        let encrypted_bytes =
            ece_encrypt(&keypair.pub_as_raw().unwrap(), &auth_secret, &bytes).unwrap();

        let decrypted_bytes = ece::decrypt(
            &keypair.raw_components().unwrap(),
            &auth_secret,
            &encrypted_bytes,
        )
        .unwrap();

        assert_eq!(bytes, decrypted_bytes, "len: {}", len);
    }
}
