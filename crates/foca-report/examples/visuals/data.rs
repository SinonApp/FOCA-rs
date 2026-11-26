//! Synthetic diagram data for the `visuals` example and the `svg` integration tests.
//! Every name, host and domain is fictitious (`*.example`, `*.test`).

#![allow(dead_code)]

use foca_report::svg::{
    Graph, GraphEdge, GraphNode, Heatmap, Lane, NetKind, NetMap, NetNode, NodeKind, ServerRole,
    Timeline, TimelineEvent,
};
use foca_report::Visuals;

fn node(id: &str, kind: NodeKind, label: &str) -> GraphNode {
    GraphNode {
        id: id.into(),
        kind,
        label: label.into(),
        critical: false,
    }
}

fn edge(a: &str, b: &str) -> GraphEdge {
    GraphEdge {
        from: a.into(),
        to: b.into(),
    }
}

fn net(id: &str, parent: Option<&str>, kind: NetKind, label: &str) -> NetNode {
    NetNode {
        id: id.into(),
        parent: parent.map(Into::into),
        kind,
        label: label.into(),
        role: None,
        critical: false,
    }
}

/// A mid-size organization: 6 people, 24 documents (most collapse into a cluster),
/// workstations, a printer, shares, servers, the AD domain and a CA.
pub fn demo() -> Visuals {
    let mut g = Graph::default();
    let people = [
        ("p.koval", "Олена Коваль"),
        ("p.petrenko", "Іван Петренко"),
        ("p.bondar", "Марія Бондар"),
        ("p.shevchuk", "Андрій Шевчук"),
        ("p.melnyk", "Світлана Мельник"),
        ("p.admin", "Administrator"),
    ];
    for (id, name) in people {
        g.nodes.push(node(id, NodeKind::Person, name));
    }
    let docs = [
        "Звіт_бухгалтерія_2024_Q4_остаточний.docx",
        "Договір_постачання_№17.pdf",
        "Наказ_про_відпустки.doc",
        "budget-2025-draft.xlsx",
        "Презентація_для_інвесторів.pptx",
        "Інструкція_VPN.pdf",
        "HR_анкета_кандидата.docx",
        "Прайс_2023.xls",
        "Положення_про_ІБ.odt",
        "scan_0001.pdf",
        "scan_0002.pdf",
        "scan_0003.pdf",
        "Кошторис_ремонту.xlsx",
        "Протокол_наради_12-03.docx",
        "Лист_до_контрагента.docx",
        "network-diagram-old.vsdx",
        "Акт_звірки.pdf",
        "Рахунок_2291.pdf",
        "Довіреність.pdf",
        "Звіт_аудиту_2022.pdf",
        "Графік_чергувань.xlsx",
        "Меморандум.docx",
        "Резюме_менеджера.pdf",
        "Технічне_завдання_портал.docx",
    ];
    for (i, d) in docs.iter().enumerate() {
        let id = format!("d{i:02}");
        g.nodes.push(node(&id, NodeKind::Document, d));
        g.edges.push(edge(people[i % people.len()].0, &id));
        let host = ["ws.buh01", "ws.hr02", "ws.it03", "prn.floor2"][i % 4];
        g.edges.push(edge(&id, host));
        if i % 5 == 0 {
            g.edges.push(edge(&id, "sh.buh"));
        }
    }
    g.nodes[6].critical = true; // the first document leaks a share path and a password
    g.nodes
        .push(node("ws.buh01", NodeKind::Workstation, "BUH-PC01"));
    g.nodes
        .push(node("ws.hr02", NodeKind::Workstation, "HR-NB02"));
    g.nodes
        .push(node("ws.it03", NodeKind::Workstation, "IT-WS03"));
    g.nodes.push(node(
        "prn.floor2",
        NodeKind::Printer,
        "HP LaserJet M507 (2 поверх)",
    ));
    g.nodes
        .push(node("sh.buh", NodeKind::Share, "\\\\FS01\\Buh$\\Звіти"));
    g.nodes
        .push(node("srv.fs01", NodeKind::Server, "FS01.corp.example.test"));
    g.nodes
        .push(node("srv.dc01", NodeKind::Server, "DC01.corp.example.test"));
    g.nodes
        .push(node("srv.mail", NodeKind::Server, "mail.example.test"));
    g.nodes
        .push(node("dom", NodeKind::Domain, "CORP (corp.example.test)"));
    g.nodes
        .push(node("pki", NodeKind::Pki, "Example-Issuing-CA-01"));
    for e in [
        ("ws.buh01", "srv.fs01"),
        ("ws.hr02", "srv.fs01"),
        ("ws.it03", "srv.dc01"),
        ("sh.buh", "srv.fs01"),
        ("prn.floor2", "srv.fs01"),
        ("srv.dc01", "dom"),
        ("srv.fs01", "dom"),
        ("pki", "dom"),
        ("p.admin", "srv.dc01"),
        ("p.petrenko", "srv.mail"),
    ] {
        g.edges.push(edge(e.0, e.1));
    }
    let dc = g.nodes.iter_mut().find(|n| n.id == "srv.dc01").unwrap();
    dc.critical = true;

    let mut m = NetMap::default();
    m.nodes.push(net(
        "dom",
        None,
        NetKind::Domain,
        "corp.example.test (CORP)",
    ));
    for (id, label, role) in [
        ("dc01", "DC01", ServerRole::Dc),
        ("ca", "Example-Issuing-CA-01", ServerRole::Pki),
        ("fs01", "FS01", ServerRole::File),
        ("mail", "mail.example.test", ServerRole::Mail),
        ("prt", "PRINTSRV", ServerRole::Print),
    ] {
        let mut n = net(id, Some("dom"), NetKind::Server, label);
        n.role = Some(role);
        m.nodes.push(n);
    }
    m.nodes
        .push(net("sh1", Some("fs01"), NetKind::Share, "\\\\FS01\\Buh$"));
    m.nodes
        .push(net("sh2", Some("fs01"), NetKind::Share, "\\\\FS01\\HR"));
    m.nodes.push(net(
        "prn",
        Some("prt"),
        NetKind::Printer,
        "HP LaserJet M507 (2 поверх)",
    ));
    for (ws, users) in [
        ("BUH-PC01", vec!["o.koval", "s.melnyk"]),
        ("HR-NB02", vec!["m.bondar"]),
        ("IT-WS03", vec!["a.shevchuk", "administrator"]),
    ] {
        m.nodes.push(net(ws, Some("dom"), NetKind::Workstation, ws));
        for u in users {
            m.nodes.push(net(
                &format!("{ws}/{u}"),
                Some(ws),
                NetKind::User,
                &format!("CORP\\{u}"),
            ));
        }
    }
    m.nodes[2].critical = true;

    let mut tl = Timeline::default();
    let mut ev = |lane, year, label: &str| {
        tl.events.push(TimelineEvent {
            lane,
            year,
            label: label.into(),
        })
    };
    for (y, n) in [
        (2017, 2),
        (2018, 3),
        (2019, 5),
        (2020, 4),
        (2021, 6),
        (2022, 8),
        (2023, 7),
        (2024, 9),
        (2025, 4),
    ] {
        for i in 0..n {
            ev(Lane::Documents, y, docs[(y as usize + i) % docs.len()]);
        }
    }
    for (y, s) in [
        (2017, "Microsoft Office 2010"),
        (2018, "Microsoft Office 2013"),
        (2019, "Microsoft Office 2016"),
        (2019, "Adobe Acrobat 11"),
        (2021, "LibreOffice 7.1"),
        (2022, "Microsoft 365"),
        (2023, "Microsoft 365"),
        (2024, "Microsoft 365"),
        (2024, "Adobe Acrobat DC"),
    ] {
        ev(Lane::Software, y, s);
    }
    for y in [2019, 2020, 2021, 2022, 2023, 2024, 2025] {
        ev(Lane::Certificates, y, "*.example.test (Let's Encrypt)");
    }
    ev(Lane::Certificates, 2023, "vpn.example.test");
    for (y, n) in [(2016, 3), (2018, 12), (2020, 30), (2022, 41), (2024, 25)] {
        for _ in 0..n {
            ev(Lane::Wayback, y, "example.test/");
        }
    }
    ev(Lane::Wayback, 2022, "example.test/portal/login");

    let mut matrix = vec![vec![0u32; 24]; 7];
    for (d, row) in matrix.iter_mut().enumerate() {
        for (h, v) in row.iter_mut().enumerate() {
            let work = d < 5 && (9..18).contains(&h);
            *v = if work {
                ((d * 7 + h * 3) % 9) as u32 + 2
            } else if d < 5 && (19..23).contains(&h) {
                ((d + h) % 3) as u32
            } else if d == 5 && (10..14).contains(&h) {
                1
            } else {
                0
            };
        }
    }
    matrix[2][23] = 4;
    let activity = Heatmap {
        matrix,
        tz: Some("UTC+2".into()),
        ..Heatmap::default()
    };
    Visuals {
        graph: g,
        netmap: m,
        timeline: tl,
        activity,
    }
}

/// Injection payloads in every text field of every diagram.
pub const PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "\"><svg onload=alert(2)>",
    "' onmouseover='alert(3)",
    "]]><foreignObject><iframe src=javascript:alert(4)>",
    "<![CDATA[x]]>",
    "&lt;b&gt;\u{202e}fdp.exe\u{0}\u{7}",
];

pub fn hostile() -> Visuals {
    let mut v = demo();
    for (i, n) in v.graph.nodes.iter_mut().enumerate() {
        n.label = format!("{}{}", PAYLOADS[i % PAYLOADS.len()], n.label);
    }
    for (i, n) in v.netmap.nodes.iter_mut().enumerate() {
        n.label = format!("{}{}", n.label, PAYLOADS[i % PAYLOADS.len()]);
    }
    for (i, e) in v.timeline.events.iter_mut().enumerate() {
        e.label = PAYLOADS[i % PAYLOADS.len()].to_string();
    }
    v.activity = v.activity.map_text(|_| PAYLOADS[1].into());
    v
}
