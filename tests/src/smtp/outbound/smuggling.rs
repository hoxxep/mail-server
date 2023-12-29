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
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::MX;
use utils::config::ServerProtocol;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    outbound::start_test_server,
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig, TestSMTP,
};
use smtp::{
    config::{ConfigContext, IfBlock},
    core::{Session, SMTP},
    queue::{manager::Queue, DeliveryAttempt, Event, WorkerResult},
};

#[tokio::test]
#[serial_test::serial]
async fn smtp_delivery() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut core = SMTP::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("smtp_delivery_remote");
    let _rx = start_test_server(core.into(), &[ServerProtocol::Smtp]);

    // Add mock DNS entries
    let mut core = SMTP::test();
    core.resolvers.dns.mx_add(
        "foobar.org",
        vec![
            MX {
                exchanges: vec!["mx1.foobar.org".to_string()],
                preference: 10,
            },
            MX {
                exchanges: vec!["mx2.foobar.org".to_string()],
                preference: 20,
            },
        ],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.mx_add(
        "foobar.net",
        vec![MX {
            exchanges: vec!["mx1.foobar.net".to_string(), "mx2.foobar.net".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut local_qr = core.init_test_queue("smtp_delivery_local");
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.rcpt.max_recipients = IfBlock::new(100);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let config = &mut core.queue.config;

    let core = Arc::new(core);
    let mut queue = Queue::default();
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    // send a smuggled message
    session
        .send_message("john@foobar.net", &["ok@foobar.org"], "test:smuggling", "250")
        .await;
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;
    local_qr.assert_empty_queue();

    let message = remote_qr.read_event()
        .await
        .unwrap_message();
    message
        .read_lines()
        .assert_contains("We lost the game.")
        .assert_contains("I am the admin now!");

    // demonstrate potential for smuggling with insecure receivers that accept \r.\r\n
    let contents = message.read_message();
    let position = contents.find("\r.").unwrap();
    let snippet = &contents[position..position+10];
    assert!(contents.contains("\r.\r\nMAIL FROM"), "{:?}", snippet);
    remote_qr.assert_empty_queue();
}
