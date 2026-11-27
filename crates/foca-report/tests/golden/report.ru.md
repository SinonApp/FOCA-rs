---
title: "Отчёт о тестировании на проникновение - contoso.example"
project: "contoso.example"
client: "ТОВ «Контосо Енерджі»"
date: 2026-11-20
template: full
lang: ru
risk: 100
risk_level: crit
findings: 102
findings_crit: 4
findings_high: 26
findings_warn: 41
findings_low: 28
findings_info: 3
secrets: hide
generator: "FOCA-rs 2.0.0-beta.4"
tags: [foca, pentest, report]
---

# Отчёт о тестировании на проникновение - contoso.example

> **Конфиденциально** · Полный отчёт пентеста · Дата отчёта: 20.11.2026 (UTC) · Исполнитель: ТОВ «Кібер Аудит»

## Резюме для руководства

**Общий уровень риска: 100/100** (Критический): по находкам отчёта

| Важность | Число |
| --- | --- |
| Критический | 4 |
| Высокий | 26 |
| Средний | 41 |
| Низкий | 28 |
| Инфо | 3 |

Исправлено к моменту отчёта: **1**

### Документы по типам

| Тип | Число |
| --- | --- |
| pdf | 10 |
| docx | 4 |
| lnk | 4 |
| jpg | 3 |
| ppt | 3 |
| doc | 2 |
| eml | 2 |
| heic | 2 |
| ics | 2 |
| indd | 2 |
| mp4 | 2 |
| msg | 2 |
| ods | 2 |
| png | 2 |
| svg | 2 |
| vcf | 2 |
| wpd | 2 |
| xls | 2 |
| xlsx | 2 |
| zip | 2 |
| bin | 1 |
| ica | 1 |
| mov | 1 |
| odt | 1 |
| pptx | 1 |
| pub | 1 |
| rdp | 1 |
| tif | 1 |
| tiff | 1 |
| vsd | 1 |
| vsdx | 1 |
| wks | 1 |
| wps | 1 |

### Топ пользователей

| Логин | Имя | Документов |
| --- | --- | --- |
| john.doe | John Doe | 14 |
| i.petrenko | i.petrenko | 13 |
| ivan.petrenko | Іван Петренко | 12 |
| o.kovalenko | Olena Kovalenko | 9 |
| m.shevchuk | Марина Шевчук | 5 |
| a.bondar | Андрій Бондар | 3 |
| p.harvey | Phil Harvey | 3 |
| t.melnyk | Тетяна Мельник | 3 |
| v.tkachenko | Віктор Ткаченко | 3 |
| n.burch | Nick Burch | 2 |

### Топ ПО

| Программное обеспечение | Документов |
| --- | --- |
| Microsoft Office Word (версия неизвестна) | 2 |
| Microsoft Office Word 2013 (15) | 2 |
| Adobe Photoshop 7.0 | 3 |
| iOS 17.4 | 2 |
| iOS 16.6 | 1 |
| Adobe Photoshop CC 2019 | 2 |
| Fujifilm (камера) | 2 |
| Microsoft Office Excel (версия неизвестна) | 2 |
| Microsoft Office Outlook 2016-2024 / 365 | 2 |
| Microsoft Office PowerPoint (версия неизвестна) | 2 |

### Устаревшее ПО

| Программное обеспечение | EOL | CVE |
| --- | --- | --- |
| Adobe Photoshop 7.0 | дата неизвестна | - |
| iOS 17.4 | 15.09.2025 | - |
| Adobe Photoshop CC 2019 | дата неизвестна | - |
| Microsoft Office Word 2013 (15) | 11.04.2023 | - |
| Adobe Acrobat Pro XI (11.0.23) | 15.10.2017 | - |
| Microsoft Excel 2010 (14) | 13.10.2020 | - |
| iOS 16.6 | 16.09.2024 | - |
| LibreOffice 7.2.5.2 | 12.06.2022 | - |
| Microsoft Word 2008 для Mac (12) | 09.04.2013 | - |
| OpenOffice.org 3.2 | 15.04.2011 | - |

### Найденная инфраструктура

| Тип | Число |
| --- | --- |
| Хосты | 27 |
| Внутренний | 18 |
| Компьютеры и серверы | 9 |
| Принтеры | 2 |
| Пути | 27 |
| E-mail | 25 |

## Скоуп

|  |  |
| --- | --- |
| Заказчик | ТОВ «Контосо Енерджі» |
| Контакт заказчика |  |
| Основание проверки | Письменное разрешение владельца от 01.11.2026 |

| Цели | Тип |
| --- | --- |
| contoso.example | domain |
| \*.contoso-group.example | wild |
| 203.0.113.0/24 | cidr |

**Исключения:** mail.contoso.example, 10.10.1.0/24

## Находки

### F-1 · Плохое замазывание: текст под закраской читается (redacted.pdf) - Критический

**Статус:** Подтверждена · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** Конфиденциальный фрагмент закрыт чёрным или белым прямоугольником поверх текста, но сам текст остался в документе: его можно скопировать или извлечь любой программой просмотра PDF.

**Доказательство:**

```text
стр. 1 (black): «Passport AB123456 Ivan Petrenko»
стр. 1 (white): «Phone +380 44 000 00 00»
стр. 2 (black): «Account UA00 0000 0000 secret»
```

**URL:** https://files.contoso.example/corpus/forensics/redacted.pdf

**Рекомендация.** Удалить документ с сайта; замазывать средствами настоящего редактирования (Redact → Apply), затем пересохранять PDF и проверять копированием текста.

*Происхождение: Правило doc.bad\_redaction; Документы: redacted.pdf*

### F-2 · Ссылки на облачные пространства и URL с токенами в personal.docx - Критический

**Статус:** Подтверждена · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213.003 · Data from Information Repositories: Code Repositories

**Описание.** Документ ссылается на облачные рабочие пространства (Google Drive, SharePoint, Notion, Trello, Jira…) или содержит URL со встроенными токенами доступа (токены маскированы).

**Доказательство:**

```text
Google Drive: https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz?usp=sharing
Azure Storage: https://contoso.blob.core.windows.net/backup/db.bak?sv=2022-11-02&sp=r&sig=Ab…3D
```

**URL:** https://files.contoso.example/corpus/forensics/personal.docx

**Рекомендация.** Проверить права доступа по ссылкам, отозвать токены и SAS-ссылки, закрыть публичный доступ к рабочим пространствам.

*Происхождение: Правило doc.links; Документы: personal.docx*

### F-3 · Пароль в строке подключения - Критический

**Статус:** Подтверждена · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1552.001 · Unsecured Credentials: Credentials In Files

**Описание.** В публично доступном документе «contract.docx» найден секрет (Пароль в строке подключения): текст, строка 6.

**Доказательство:**

```text
текст, строка 6:
Доступ до порталу: Server=10.10.1.5;Database=tender;User Id=sa;Password=[скрыто]
```

**URL:** https://files.contoso.example/corpus/ooxml/contract.docx

**Рекомендация.** Немедленно сменить (отозвать) секрет, удалить документ с сайта и из кэшей поисковиков, проверить журналы использования.

*Происхождение: Правило secret; Документы: contract.docx*

### F-4 · ICA-файл с паролем в открытом виде (buh.ica) - Критический

**Статус:** Подтверждена · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1552.001 · Unsecured Credentials: Credentials In Files

**Описание.** В публично доступном документе «buh.ica» найден секрет (Пароль в открытом виде в .ica-файле): поле ica:1C Бухгалтерія.ClearPassword.

**Доказательство:**

```text
поле ica:1C Бухгалтерія.ClearPassword:
ica:1C Бухгалтерія.ClearPassword: [скрыто]
```

**URL:** https://files.contoso.example/corpus/remote/buh.ica

**Рекомендация.** Немедленно сменить пароль, удалить файл с сайта, запретить ClearPassword в конфигурации Citrix StoreFront.

*Происхождение: Правило ica-password; Документы: buh.ica*

### F-5 · Внутренние почтовые серверы и адреса в заголовках письма (budget.msg) - Высокий

**Статус:** Подтверждена · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Цепочка Received раскрывает внутренние почтовые релеи, рабочие станции и их частные IP-адреса.

**Доказательство:**

```text
ws-042.corp.example.test, EXCH01.corp.example.test, 10.20.30.42, 10.20.0.15, buh-pc-07.corp.example.test, EXCH02.corp.example.test, 192.168.10.7, 10.20.0.16
```

**URL:** https://files.contoso.example/corpus/mail/budget.msg

**Рекомендация.** Удалять внутренние заголовки Received на пограничном почтовом шлюзе; не публиковать исходные письма.

*Происхождение: Правило mail.internal\_relay; Документы: budget.msg*

### F-6 · Ярлык LNK раскрывает имя компьютера и MAC-адрес (report.lnk) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1592.001 · Gather Victim Host Information: Hardware

**Описание.** Ярлык Windows хранит NetBIOS-имя компьютера, MAC-адрес сетевой карты и серийный номер тома, на котором он создан.

**Доказательство:**

```text
Компьютер: ws-042
MAC: 0a:00:27:00:00:2a
Серийный номер тома: 1A2B-3C4D
Путь: C:\Users\i.petrenko\Documents\Звіт.docx
```

**URL:** https://files.contoso.example/corpus/lnk/report.lnk

**Рекомендация.** Не публиковать ярлыки .lnk; удалить файл с сайта.

*Происхождение: Правило doc.lnk\_host\_mac; Документы: report.lnk*

### F-7 · Ярлык LNK раскрывает имя компьютера и MAC-адрес (network.lnk) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1592.001 · Gather Victim Host Information: Hardware

**Описание.** Ярлык Windows хранит NetBIOS-имя компьютера, MAC-адрес сетевой карты и серийный номер тома, на котором он создан.

**Доказательство:**

```text
Компьютер: buh-pc-07
MAC: 00:15:5d:01:02:03
```

**URL:** https://files.contoso.example/corpus/lnk/network.lnk

**Рекомендация.** Не публиковать ярлыки .lnk; удалить файл с сайта.

*Происхождение: Правило doc.lnk\_host\_mac; Документы: network.lnk*

### F-8 · Ярлык LNK раскрывает имя компьютера и MAC-адрес (backup.zip) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1592.001 · Gather Victim Host Information: Hardware

**Описание.** Ярлык Windows хранит NetBIOS-имя компьютера, MAC-адрес сетевой карты и серийный номер тома, на котором он создан.

**Доказательство:**

```text
Компьютер: ws-042
MAC: 0a:00:27:00:00:2a
Серийный номер тома: 1A2B-3C4D
Путь: C:\Users\i.petrenko\Documents\Звіт.docx
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Не публиковать ярлыки .lnk; удалить файл с сайта.

*Происхождение: Правило doc.lnk\_host\_mac; Документы: backup.zip*

### F-9 · Удалённый текст восстанавливается из старых ревизий PDF (revisions.pdf) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** PDF сохранён инкрементально: в предыдущих ревизиях остался текст, удалённый из последней версии.

**Доказательство:**

```text
ревизия 2: «Salary of Ivan Petrenko: 1000 UAH»
```

**URL:** https://files.contoso.example/corpus/forensics/revisions.pdf

**Рекомендация.** Пересохранить PDF полностью (без инкрементальных обновлений) и заменить опубликованный файл.

*Происхождение: Правило doc.pdf\_removed\_text; Документы: revisions.pdf*

### F-10 · Номер банковской карты в документе (personal.docx) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе найдено значений: 1. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.

**Доказательство:**

```text
Картка ••••••••••11
Visa
```

**URL:** https://files.contoso.example/corpus/forensics/personal.docx

**Рекомендация.** Удалить персональные данные из публикуемого документа (обезличить) или убрать документ; оценить уведомление владельцев данных.

*Происхождение: Правило pii; Документы: personal.docx*

### F-11 · РНОКПП (ІПН) физлица в документе (personal.docx) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе найдено значений: 1. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.

**Доказательство:**

```text
Отримувач: Іван Петренко, РНОКПП ••••••••70
```

**URL:** https://files.contoso.example/corpus/forensics/personal.docx

**Рекомендация.** Удалить персональные данные из публикуемого документа (обезличить) или убрать документ; оценить уведомление владельцев данных.

*Происхождение: Правило pii; Документы: personal.docx*

### F-12 · Миниатюра EXIF может отличаться от фото (photo.jpg) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1591 · Gather Victim Org Information

**Описание.** Фото отредактировано в графическом редакторе, но встроенная миниатюра EXIF сохранена: она может показывать исходный (необрезанный, незамазанный) кадр.

**Доказательство:**

```text
Apple iPhone 13 Pro
ПО: ios166, ps2019
```

**URL:** https://files.contoso.example/corpus/images/photo.jpg

**Рекомендация.** Удалять EXIF и миниатюры перед публикацией; сравнить миниатюру с изображением.

*Происхождение: Правило thumbnail; Документы: photo.jpg*

### F-13 · RDP-файл с сохранённым паролем (SRV-TS01.rdp) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1552.001 · Unsecured Credentials: Credentials In Files

**Описание.** В публично доступном документе «SRV-TS01.rdp» найден секрет (Сохранённый пароль в .rdp-файле): поле rdp:password 51.

**Доказательство:**

```text
поле rdp:password 51:
rdp:password 51: [скрыто]
```

**URL:** https://files.contoso.example/corpus/remote/SRV-TS01.rdp

**Рекомендация.** Удалить файл с сайта; сменить пароль учётной записи из файла; запретить сохранение паролей в RDP-клиенте групповой политикой.

*Происхождение: Правило rdp-password; Документы: SRV-TS01.rdp*

### F-14 · Удалённый текст восстанавливается из старых ревизий PDF (signed\_modified.pdf) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** PDF сохранён инкрементально: в предыдущих ревизиях остался текст, удалённый из последней версии.

**Доказательство:**

```text
ревизия 2: «Contract No 42 between Example LLC and Ivan Petrenko»
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_modified.pdf

**Рекомендация.** Пересохранить PDF полностью (без инкрементальных обновлений) и заменить опубликованный файл.

*Происхождение: Правило doc.pdf\_removed\_text; Документы: signed\_modified.pdf*

### F-15 · Пароль в тексте документа · objstm.pdf - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1552.001 · Unsecured Credentials: Credentials In Files

**Описание.** В публично доступном документе «objstm.pdf» найден секрет (Пароль в тексте документа): текст, строка 1.

**Доказательство:**

```text
текст, строка 1:
Config: password=[скрыто] host=dev.contoso.example
```

**URL:** https://files.contoso.example/corpus/pdf/objstm.pdf

**Рекомендация.** Немедленно сменить (отозвать) секрет, удалить документ с сайта и из кэшей поисковиков, проверить журналы использования.

*Происхождение: Правило secret; Документы: objstm.pdf*

### F-16 · Скрытый текст и скрытые строки/столбцы в hidden.xlsx - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** Документ содержит скрытое форматирование (w:vanish) или скрытые строки и столбцы таблицы: при просмотре их не видно, но данные остаются в файле.

**Доказательство:**

```text
скрытые строки Payroll!3:4: «Ivan Petrenko | 12000 | Bonus fund»
скрытые столбцы Payroll!C:D: «Salary | 5000»
```

**URL:** https://files.contoso.example/corpus/forensics/hidden.xlsx

**Рекомендация.** Удалять, а не скрывать служебные данные; проверять документ Инспектором документов перед публикацией.

*Происхождение: Правило doc.hidden\_content; Документы: hidden.xlsx*

### F-17 · Номер счёта IBAN в документе (personal.docx) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе найдено значений: 1. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.

**Доказательство:**

```text
IBAN ••••••••••01
МФО 322313
```

**URL:** https://files.contoso.example/corpus/forensics/personal.docx

**Рекомендация.** Удалить персональные данные из публикуемого документа (обезличить) или убрать документ; оценить уведомление владельцев данных.

*Происхождение: Правило pii; Документы: personal.docx*

### F-18 · Документ изменён после подписания (signed\_modified.pdf) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1565.001 · Data Manipulation: Stored Data Manipulation

**Описание.** После байтов, покрытых подписью (/ByteRange), в файл дописаны изменения: видимое содержимое может отличаться от подписанного.

**Доказательство:**

```text
Подписант: Іван Петренко
Организация: ТОВ Приклад
ЄДРПОУ: 12345678
Должность: Директор
E-mail: ivan.petrenko@example.com
РНОКПП: ********99
АЦСК: Example Test QTSP CA
Время подписи: 2026-11-22T01:06:56Z
Метка TSA: 2026-11-22T01:06:56Z
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_modified.pdf

**Рекомендация.** Сверить документ с подписанным оригиналом; публиковать только неизменённую подписанную версию.

*Происхождение: Правило doc.modified\_after\_signing; Документы: signed\_modified.pdf*

### F-19 · Архив с опасными путями (Zip-Slip): backup.zip - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1204.002 · User Execution: Malicious File

**Описание.** Имена файлов в архиве выходят за пределы папки распаковки (../, абсолютные пути): архив враждебен или повреждён.

**Доказательство:**

```text
../../evil.txt
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Не распаковывать архив; проверить источник файла.

*Происхождение: Правило zip.path\_traversal; Документы: backup.zip*

### F-20 · Внешние источники данных в schedule.xlsx - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590 · Gather Victim Network Information

**Описание.** Подключения к базам данных, файлы .odc, сводные таблицы и внешние ссылки диаграмм раскрывают серверы, базы, учётные записи и пути к файлам.

**Доказательство:**

```text
billing (odbc): server=SRV-SQL02; database=billing; user=billing_ro; provider=SQLOLEDB.1; password=***
```

**URL:** https://files.contoso.example/corpus/ooxml/schedule.xlsx

**Рекомендация.** Удалять подключения к данным и кэши сводных таблиц перед публикацией (вставлять значения).

*Происхождение: Правило doc.data\_connection; Документы: schedule.xlsx*

### F-21 · Пароль в тексте документа · legacy.doc - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1552.001 · Unsecured Credentials: Credentials In Files

**Описание.** В публично доступном документе «legacy.doc» найден секрет (Пароль в тексте документа): текст, строка 1.

**Доказательство:**

```text
текст, строка 1:
Статут підприємства. Пароль адміністратора: [скрыто]
```

**URL:** https://files.contoso.example/corpus/ole/legacy.doc

**Рекомендация.** Немедленно сменить (отозвать) секрет, удалить документ с сайта и из кэшей поисковиков, проверить журналы использования.

*Происхождение: Правило secret; Документы: legacy.doc*

### F-22 · IP-адрес отправителя в заголовках письма (budget.msg) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Заголовок X-Originating-IP раскрывает адрес рабочей станции отправителя.

**Доказательство:**

```text
10.20.30.42
```

**URL:** https://files.contoso.example/corpus/mail/budget.msg

**Рекомендация.** Отключить добавление X-Originating-IP на почтовом сервере.

*Происхождение: Правило mail.originating\_ip; Документы: budget.msg*

### F-23 · Внутренние почтовые серверы и адреса в заголовках письма (backup.zip) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Цепочка Received раскрывает внутренние почтовые релеи, рабочие станции и их частные IP-адреса.

**Доказательство:**

```text
EXCH01.corp.example.test, ws-042.corp.example.test, 10.20.30.42, 10.20.0.15, ws-017.corp.example.test, EXCH02.corp.example.test, 192.168.10.17, 10.20.0.16
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Удалять внутренние заголовки Received на пограничном почтовом шлюзе; не публиковать исходные письма.

*Происхождение: Правило mail.internal\_relay; Документы: backup.zip*

### F-24 · Пароль в строке подключения к данным - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1552.001 · Unsecured Credentials: Credentials In Files

**Описание.** В публично доступном документе «schedule.xlsx» найден секрет (Пароль в строке подключения к данным): поле xl/connections.xml.

**Доказательство:**

```text
поле xl/connections.xml:
xl/connections.xml: [скрыто]
```

**URL:** https://files.contoso.example/corpus/ooxml/schedule.xlsx

**Рекомендация.** Немедленно сменить (отозвать) секрет, удалить документ с сайта и из кэшей поисковиков, проверить журналы использования.

*Происхождение: Правило secret; Документы: schedule.xlsx*

### F-25 · Скрытый текст и скрытые строки/столбцы в signed\_hidden.docx - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** Документ содержит скрытое форматирование (w:vanish) или скрытые строки и столбцы таблицы: при просмотре их не видно, но данные остаются в файле.

**Доказательство:**

```text
скрытый текст word/document.xml: «Internal note: budget 2M UAH, contact Ivan Petrenko.»
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_hidden.docx

**Рекомендация.** Удалять, а не скрывать служебные данные; проверять документ Инспектором документов перед публикацией.

*Происхождение: Правило doc.hidden\_content; Документы: signed\_hidden.docx*

### F-26 · IP-адрес отправителя в заголовках письма (backup.zip) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Заголовок X-Originating-IP раскрывает адрес рабочей станции отправителя.

**Доказательство:**

```text
10.20.30.42
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Отключить добавление X-Originating-IP на почтовом сервере.

*Происхождение: Правило mail.originating\_ip; Документы: backup.zip*

### F-27 · SAS-токен Azure - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1552.001 · Unsecured Credentials: Credentials In Files

**Описание.** В публично доступном документе «personal.docx» найден секрет (SAS-токен Azure): текст, строка 9.

**Доказательство:**

```text
текст, строка 9:
пія: https://contoso.blob.core.windows.net/backup/db.bak?sv=2022-11-02&sp=r&sig=[скрыто]
```

**URL:** https://files.contoso.example/corpus/forensics/personal.docx

**Рекомендация.** Немедленно сменить (отозвать) секрет, удалить документ с сайта и из кэшей поисковиков, проверить журналы использования.

*Происхождение: Правило secret; Документы: personal.docx*

### F-28 · IP-адрес отправителя в заголовках письма (budget.eml) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Заголовок X-Originating-IP раскрывает адрес рабочей станции отправителя.

**Доказательство:**

```text
10.20.30.42
```

**URL:** https://files.contoso.example/corpus/mail/budget.eml

**Рекомендация.** Отключить добавление X-Originating-IP на почтовом сервере.

*Происхождение: Правило mail.originating\_ip; Документы: budget.eml*

### F-29 · Гриф ограничения доступа в документе (personal.docx) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** Документ с грифом ограничения доступа опубликован в открытом доступе.

**Доказательство:**

```text
ДСК
ДСК
```

**URL:** https://files.contoso.example/corpus/forensics/personal.docx

**Рекомендация.** Удалить документ из открытого доступа и проверить процедуру публикации документов с грифом.

*Происхождение: Правило pii; Документы: personal.docx*

### F-30 · Серия и номер паспорта в документе (personal.docx) - Высокий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе найдено значений: 1. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.

**Доказательство:**

```text
Паспорт серія ••••••56
```

**URL:** https://files.contoso.example/corpus/forensics/personal.docx

**Рекомендация.** Удалить персональные данные из публикуемого документа (обезличить) или убрать документ; оценить уведомление владельцев данных.

*Происхождение: Правило pii; Документы: personal.docx*

### F-31 · Данные подписанта (КЕП) в документе signed.pdf: Іван Петренко - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1589.001 · Gather Victim Identity Information: Credentials

**Описание.** Сертификат подписи раскрывает ФИО, должность, организацию и центр сертификации подписанта; для украинского КЕП: коды ЄДРПОУ и РНОКПП (РНОКПП хранится только маскированным).

**Доказательство:**

```text
Подписант: Іван Петренко
Организация: ТОВ Приклад
ЄДРПОУ: 12345678
Должность: Директор
E-mail: ivan.petrenko@example.com
РНОКПП: ********99
АЦСК: Example Test QTSP CA
Время подписи: 2026-11-22T01:06:56Z
Метка TSA: 2026-11-22T01:06:56Z
```

**URL:** https://files.contoso.example/corpus/forensics/signed.pdf

**Рекомендация.** Учитывать, что подписанные документы раскрывают данные сертификата; для публикации использовать печать организации или отдельную публичную подпись.

*Происхождение: Правило doc.signer\_identity; Документы: signed.pdf*

### F-32 · Данные подписанта (КЕП) в документе signed\_hidden.docx: John Doe - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1589.001 · Gather Victim Identity Information: Credentials

**Описание.** Сертификат подписи раскрывает ФИО, должность, организацию и центр сертификации подписанта; для украинского КЕП: коды ЄДРПОУ и РНОКПП (РНОКПП хранится только маскированным).

**Доказательство:**

```text
Подписант: John Doe
Организация: Example LLC
ЄДРПОУ: 87654321
Должность: Accountant
РНОКПП: ********99
АЦСК: Example Test QTSP CA
Время подписи: 2024-03-01T08:00:01Z
Метка TSA: 2026-11-22T01:06:57Z
Подписант: Іван Петренко
Организация: ТОВ Приклад
ЄДРПОУ: 12345678
Должность: Директор
E-mail: ivan.petrenko@example.com
РНОКПП: ********99
АЦСК: Example Test QTSP CA
Время подписи: 2026-11-22T01:06:57Z
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_hidden.docx

**Рекомендация.** Учитывать, что подписанные документы раскрывают данные сертификата; для публикации использовать печать организации или отдельную публичную подпись.

*Происхождение: Правило doc.signer\_identity; Документы: signed\_hidden.docx*

### F-33 · Adobe Acrobat Pro XI (EOL) у 1 документа - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 1 документ создан в Adobe Acrobat Pro XI (11.0.23), поддержка завершена 2017-10-15. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: Adobe Acrobat Pro XI (11.0.23)
Документов: 1
```

**URL:** https://files.contoso.example/corpus/pdf/report.pdf

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: report.pdf*

### F-34 · Скан без текстового слоя: exiftool-PDF.pdf - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Документ состоит только из изображений страниц: его содержимое не проверяется поиском, DLP и этим анализом.

**Доказательство:**

```text
exiftool-PDF.pdf
```

**URL:** https://files.contoso.example/corpus/real/exiftool-PDF.pdf

**Рекомендация.** Проверить скан вручную; не публиковать сканы личных документов.

*Происхождение: Правило doc.scan\_without\_text; Документы: exiftool-PDF.pdf*

### F-35 · Документ с макросами VBA: legacy.doc - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1059.005 · Command and Scripting Interpreter: Visual Basic

**Описание.** Опубликованный документ содержит проект VBA: исходный код макросов раскрывает внутреннюю логику, пути и иногда учётные данные; такие файлы приучают пользователей включать макросы.

**Доказательство:**

```text
Модули: AutoOpen, ThisDocument
```

**URL:** https://files.contoso.example/corpus/ole/legacy.doc

**Рекомендация.** Не публиковать документы с макросами; проверить код макросов на секреты и пути.

*Происхождение: Правило macros; Документы: legacy.doc*

### F-36 · Скан без текстового слоя: scan.pdf - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Документ состоит только из изображений страниц: его содержимое не проверяется поиском, DLP и этим анализом.

**Доказательство:**

```text
scan.pdf
```

**URL:** https://files.contoso.example/corpus/forensics/scan.pdf

**Рекомендация.** Проверить скан вручную; не публиковать сканы личных документов.

*Происхождение: Правило doc.scan\_without\_text; Документы: scan.pdf*

### F-37 · Внутренний домен в Message-ID (budget.msg) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Идентификатор письма содержит внутреннее имя почтового сервера или домена Active Directory.

**Доказательство:**

```text
exch01.corp.example.test
```

**URL:** https://files.contoso.example/corpus/mail/budget.msg

**Рекомендация.** Настроить почтовый сервер на внешнее имя в Message-ID.

*Происхождение: Правило mail.internal\_domain; Документы: budget.msg*

### F-38 · Документ с макросами VBA: budget.xls - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1059.005 · Command and Scripting Interpreter: Visual Basic

**Описание.** Опубликованный документ содержит проект VBA: исходный код макросов раскрывает внутреннюю логику, пути и иногда учётные данные; такие файлы приучают пользователей включать макросы.

**Доказательство:**

```text
Модули: Module1
```

**URL:** https://files.contoso.example/corpus/ole/budget.xls

**Рекомендация.** Не публиковать документы с макросами; проверить код макросов на секреты и пути.

*Происхождение: Правило macros; Документы: budget.xls*

### F-39 · Скан без текстового слоя: exiftool-PDF2.pdf - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Документ состоит только из изображений страниц: его содержимое не проверяется поиском, DLP и этим анализом.

**Доказательство:**

```text
exiftool-PDF2.pdf
```

**URL:** https://files.contoso.example/corpus/real/exiftool-PDF2.pdf

**Рекомендация.** Проверить скан вручную; не публиковать сканы личных документов.

*Происхождение: Правило doc.scan\_without\_text; Документы: exiftool-PDF2.pdf*

### F-40 · Adobe Photoshop CC 2019 (EOL) у 2 документов - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 2 документа созданы в Adobe Photoshop CC 2019, снято с поддержки. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: Adobe Photoshop CC 2019
Документов: 2
```

**URL:** https://files.contoso.example/corpus/images/photo.jpg

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: photo.jpg, screenshot.png*

### F-41 · GPS-координаты в 6 фото - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1591.001 · Gather Victim Org Information: Determine Physical Locations

**Описание.** Опубликованные фото содержат координаты съёмки и модель устройства: раскрываются расположение объектов и устройства сотрудников.

**Доказательство:**

```text
photo.jpg: 47.92000, 33.43000 · Apple iPhone 13 Pro
iphone.mov: 46.48250, 30.72330 · Apple iPhone 15 Pro
photo.heic: 46.48250, 30.72278 · Apple iPhone 15 Pro
survey.mp4: 50.45010, 30.52340 · ExampleCam ActionCam 4
contacts.vcf: 50.45010, 30.52340 · -
```

**URL:** https://files.contoso.example/corpus/images/photo.jpg

**Рекомендация.** Удалять EXIF перед публикацией, настроить CMS на автоматическую очистку метаданных изображений.

*Происхождение: Правило gps; Документы: photo.jpg, iphone.mov, photo.heic, survey.mp4, contacts.vcf, exiftool-GPS.jpg*

### F-42 · Устаревшая ОС iOS 16.6 у 1 документа - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1592.002 · Gather Victim Host Information: Software

**Описание.** Метаданные 1 документа указывают, что он создан в iOS 16.6: ОС без обновлений безопасности.

**Доказательство:**

```text
ОС: iOS 16.6
Документов: 1
```

**URL:** https://files.contoso.example/corpus/images/photo.jpg

**Рекомендация.** Вывести из эксплуатации или изолировать рабочие места с неподдерживаемой ОС.

*Происхождение: Правило eol-os; Документы: photo.jpg*

### F-43 · Документ с макросами VBA: schedule.xlsx - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1059.005 · Command and Scripting Interpreter: Visual Basic

**Описание.** Опубликованный документ содержит проект VBA: исходный код макросов раскрывает внутреннюю логику, пути и иногда учётные данные; такие файлы приучают пользователей включать макросы.

**Доказательство:**

```text
Модули: Module1, ThisWorkbook
```

**URL:** https://files.contoso.example/corpus/ooxml/schedule.xlsx

**Рекомендация.** Не публиковать документы с макросами; проверить код макросов на секреты и пути.

*Происхождение: Правило macros; Документы: schedule.xlsx*

### F-44 · Reply-To отличается от отправителя (budget.eml) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1566 · Phishing

**Описание.** Ответы на письмо уходят на другой адрес, чем адрес отправителя: типичный признак фишинга или личного ящика сотрудника.

**Доказательство:**

```text
i.petrenko.private@example.net
```

**URL:** https://files.contoso.example/corpus/mail/budget.eml

**Рекомендация.** Проверить адрес Reply-To; не использовать личные ящики для служебной переписки.

*Происхождение: Правило mail.reply\_to\_mismatch; Документы: budget.eml*

### F-45 · Структура Exchange (X.500) в письме (budget.msg) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Адреса X.500 Exchange раскрывают название организации, административной группы и учётные записи.

**Доказательство:**

```text
/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=I.PETRENKO
```

**URL:** https://files.contoso.example/corpus/mail/budget.msg

**Рекомендация.** Не публиковать исходные файлы .msg.

*Происхождение: Правило mail.exchange\_x500; Документы: budget.msg*

### F-46 · Личные контакты в визитных карточках (contacts.vcf) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people

**Описание.** Файл контактов содержит телефоны, адреса и даты рождения (значения в базе маскированы).

**Доказательство:**

```text
adr: ••••••••••на
bday: ••••••••01
tel: ••••••••••00; ••••••••••01
```

**URL:** https://files.contoso.example/corpus/pim/contacts.vcf

**Рекомендация.** Не публиковать файлы контактов .vcf.

*Происхождение: Правило pim.contact\_pii; Документы: contacts.vcf*

### F-47 · iOS 16.6 (EOL) у 1 документа - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 1 документ создан в iOS 16.6, поддержка завершена 2024-09-16. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: iOS 16.6
Документов: 1
```

**URL:** https://files.contoso.example/corpus/images/photo.jpg

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: photo.jpg*

### F-48 · Reply-To отличается от отправителя (backup.zip) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1566 · Phishing

**Описание.** Ответы на письмо уходят на другой адрес, чем адрес отправителя: типичный признак фишинга или личного ящика сотрудника.

**Доказательство:**

```text
i.petrenko.private@example.net
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Проверить адрес Reply-To; не использовать личные ящики для служебной переписки.

*Происхождение: Правило mail.reply\_to\_mismatch; Документы: backup.zip*

### F-49 · Устаревшая ОС iOS 17.4 у 2 документов - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1592.002 · Gather Victim Host Information: Software

**Описание.** Метаданные 2 документов указывают, что они созданы в iOS 17.4: ОС без обновлений безопасности.

**Доказательство:**

```text
ОС: iOS 17.4
Документов: 2
```

**URL:** https://files.contoso.example/corpus/media/iphone.mov

**Рекомендация.** Вывести из эксплуатации или изолировать рабочие места с неподдерживаемой ОС.

*Происхождение: Правило eol-os; Документы: iphone.mov, photo.heic*

### F-50 · Ярлык LNK указывает на сетевой ресурс (network.lnk) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1135 · Network Share Discovery

**Описание.** Ярлык ссылается на файл на сетевом ресурсе: раскрываются имя файлового сервера и структура папок.

**Доказательство:**

```text
\\FS01.corp.example.test\buh$\Звіти\2024\Q1.xlsx
\\FS01.corp.example.test\buh$
```

**URL:** https://files.contoso.example/corpus/lnk/network.lnk

**Рекомендация.** Не публиковать ярлыки .lnk.

*Происхождение: Правило doc.lnk\_unc\_path; Документы: network.lnk*

### F-51 · Внутренний домен в Message-ID (budget.eml) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Идентификатор письма содержит внутреннее имя почтового сервера или домена Active Directory.

**Доказательство:**

```text
exch01.corp.example.test
```

**URL:** https://files.contoso.example/corpus/mail/budget.eml

**Рекомендация.** Настроить почтовый сервер на внешнее имя в Message-ID.

*Происхождение: Правило mail.internal\_domain; Документы: budget.eml*

### F-52 · Внутренний домен в Message-ID (backup.zip) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Идентификатор письма содержит внутреннее имя почтового сервера или домена Active Directory.

**Доказательство:**

```text
exch01.corp.example.test
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Настроить почтовый сервер на внешнее имя в Message-ID.

*Происхождение: Правило mail.internal\_domain; Документы: backup.zip*

### F-53 · Ссылки на онлайн-встречи в календаре (meeting.ics) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Приглашение содержит ссылки подключения к Teams/Zoom (иногда с паролем): посторонний может войти на встречу.

**Доказательство:**

```text
https://teams.microsoft.com/l/meetup-join/19%3ameeting_EXAMPLE%40thread.v2/0?context=%7b%7d
https://example.zoom.us/j/1234567890?pwd=EXAMPLE
https://teams.microsoft.com/l/meetup-join/19%3ameeting_EXAMPLE%40thread.v2/0
```

**URL:** https://files.contoso.example/corpus/pim/meeting.ics

**Рекомендация.** Не публиковать приглашения; включить зал ожидания и пароли встреч.

*Происхождение: Правило cal.meeting\_link; Документы: meeting.ics*

### F-54 · Исправления и удалённый текст сохранены в contract.docx - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе сохранены режим рецензирования (2 исправления, из них 1 удаление) и 1 комментарий: видны прежние формулировки и внутренняя переписка.

**Доказательство:**

```text
удалено a.bondar, 2024-03-14T17:02:00: «1 250 000 грн»
вставлено i.petrenko-2, 2024-03-14T17:05:00: «980 000 грн»
комментарий o.kovalenko, 2024-03-14T16:40:00: «Перевірити реквізити, логін o.kovalenko@contoso.example»
```

**URL:** https://files.contoso.example/corpus/ooxml/contract.docx

**Рекомендация.** Принимать все исправления и удалять комментарии перед публикацией; для внешних документов использовать PDF.

*Происхождение: Правило revisions; Документы: contract.docx*

### F-55 · Серийный номер устройства в медиафайле (iphone.mov) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1592.001 · Gather Victim Host Information: Hardware

**Описание.** Видео или фото содержит серийный номер камеры/телефона: по нему связываются другие публикации с того же устройства.

**Доказательство:**

```text
EXAMPLE-SN-0042
```

**URL:** https://files.contoso.example/corpus/media/iphone.mov

**Рекомендация.** Удалять метаданные медиафайлов перед публикацией.

*Происхождение: Правило media.device\_serial; Документы: iphone.mov*

### F-56 · Внешние источники данных в hidden.xlsx - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590 · Gather Victim Network Information

**Описание.** Подключения к базам данных, файлы .odc, сводные таблицы и внешние ссылки диаграмм раскрывают серверы, базы, учётные записи и пути к файлам.

**Доказательство:**

```text
chart:xl/charts/chart1.xml:externalRef: 'C:\Users\ipetrenko\Desktop\[budget.xlsx]Sheet1'!$A$1:$A$5
xl:pivotCache1:refreshedBy: Ivan Petrenko
xl:pivotCache1:source: Payroll!A1:D10
srv-sql01 Payroll (odbc): server=srv-sql01.corp.example.com; database=Payroll; user=svc_report; provider=SQLOLEDB.1; target=C:\Users\ipetrenko\Documents\My Data Sources\srv-sql01 Payroll.odc
```

**URL:** https://files.contoso.example/corpus/forensics/hidden.xlsx

**Рекомендация.** Удалять подключения к данным и кэши сводных таблиц перед публикацией (вставлять значения).

*Происхождение: Правило doc.data\_connection; Документы: hidden.xlsx*

### F-57 · Документ с макросами VBA: vbaProject.bin - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1059.005 · Command and Scripting Interpreter: Visual Basic

**Описание.** Опубликованный документ содержит проект VBA: исходный код макросов раскрывает внутреннюю логику, пути и иногда учётные данные; такие файлы приучают пользователей включать макросы.

**Доказательство:**

```text
Модули: Module1, ThisWorkbook
```

**URL:** https://files.contoso.example/corpus/ole/vbaProject.bin

**Рекомендация.** Не публиковать документы с макросами; проверить код макросов на секреты и пути.

*Происхождение: Правило macros; Документы: vbaProject.bin*

### F-58 · Личные контакты в визитных карточках (backup.zip) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people

**Описание.** Файл контактов содержит телефоны, адреса и даты рождения (значения в базе маскированы).

**Доказательство:**

```text
nested/inner.zip → contacts/i.petrenko.vcf: adr: ••••••••••на
nested/inner.zip → contacts/i.petrenko.vcf: bday: ••••••••01
nested/inner.zip → contacts/i.petrenko.vcf: tel: ••••••••••00; ••••••••••01
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Не публиковать файлы контактов .vcf.

*Происхождение: Правило pim.contact\_pii; Документы: backup.zip*

### F-59 · Разные авторы или программы в ревизиях PDF (signed\_modified.pdf) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Ревизии PDF сохранены разными людьми или программами: видна цепочка согласования и использованное ПО.

**Доказательство:**

```text
ревизия 1: Ivan Petrenko / FOCA-rs fixture
ревизия 2: Mallory Example / FOCA-rs fixture
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_modified.pdf

**Рекомендация.** Пересохранять итоговый PDF полностью перед публикацией.

*Происхождение: Правило doc.pdf\_revision\_authors; Документы: signed\_modified.pdf*

### F-60 · PDF содержит JavaScript: report.pdf - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1204.002 · User Execution: Malicious File

**Описание.** В PDF есть действия JavaScript. В опубликованном документе компании это нетипично и может указывать на компрометацию или трекинг.

**URL:** https://files.contoso.example/corpus/pdf/report.pdf

**Рекомендация.** Проверить сценарий, пересоздать документ без JavaScript.

*Происхождение: Правило pdf-javascript; Документы: report.pdf*

### F-61 · Скрытые листы в budget.xls: Зарплати, Службовий - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** Книга содержит скрытые листы: они не видны при просмотре, но доступны любому, кто откроет файл.

**Доказательство:**

```text
Зарплати
Службовий
```

**URL:** https://files.contoso.example/corpus/ole/budget.xls

**Рекомендация.** Удалять служебные листы перед публикацией, а не скрывать их.

*Происхождение: Правило hidden-sheets; Документы: budget.xls*

### F-62 · Скрытые листы в schedule.xlsx: Зарплати, Паролі - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** Книга содержит скрытые листы: они не видны при просмотре, но доступны любому, кто откроет файл.

**Доказательство:**

```text
Зарплати
Паролі
```

**URL:** https://files.contoso.example/corpus/ooxml/schedule.xlsx

**Рекомендация.** Удалять служебные листы перед публикацией, а не скрывать их.

*Происхождение: Правило hidden-sheets; Документы: schedule.xlsx*

### F-63 · Исправления и удалённый текст сохранены в letter.odt - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе сохранены режим рецензирования (1 исправление, из них 1 удаление) и 1 комментарий: видны прежние формулировки и внутренняя переписка.

**Доказательство:**

```text
удалено a.bondar, 2022-05-17T15:00:00: «Строк: 10 днів»
комментарий i.petrenko, 2022-05-17T16:00:00: «Додати телефон 0441234567»
```

**URL:** https://files.contoso.example/corpus/odf/letter.odt

**Рекомендация.** Принимать все исправления и удалять комментарии перед публикацией; для внешних документов использовать PDF.

*Происхождение: Правило revisions; Документы: letter.odt*

### F-64 · Разные авторы или программы в ревизиях PDF (report.pdf) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Ревизии PDF сохранены разными людьми или программами: видна цепочка согласования и использованное ПО.

**Доказательство:**

```text
ревизия 1: o.kovalenko / Microsoft® Word 2013 / Microsoft® Word 2013
ревизия 2: Administrator / Microsoft® Word 2013 / Adobe Acrobat Pro XI 11.0.23
```

**URL:** https://files.contoso.example/corpus/pdf/report.pdf

**Рекомендация.** Пересохранять итоговый PDF полностью перед публикацией.

*Происхождение: Правило doc.pdf\_revision\_authors; Документы: report.pdf*

### F-65 · iOS 17.4 (EOL) у 2 документов - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 2 документа созданы в iOS 17.4, поддержка завершена 2025-09-15. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: iOS 17.4
Документов: 2
```

**URL:** https://files.contoso.example/corpus/media/iphone.mov

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: iphone.mov, photo.heic*

### F-66 · Разные авторы или программы в ревизиях PDF (revisions.pdf) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Ревизии PDF сохранены разными людьми или программами: видна цепочка согласования и использованное ПО.

**Доказательство:**

```text
ревизия 1: John Doe / Writer / FOCA-rs fixture
ревизия 2: Jane Roe / Writer / Other Producer 2.0
```

**URL:** https://files.contoso.example/corpus/forensics/revisions.pdf

**Рекомендация.** Пересохранять итоговый PDF полностью перед публикацией.

*Происхождение: Правило doc.pdf\_revision\_authors; Документы: revisions.pdf*

### F-67 · Данные подписанта (КЕП) в документе signed\_modified.pdf: Іван Петренко - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1589.001 · Gather Victim Identity Information: Credentials

**Описание.** Сертификат подписи раскрывает ФИО, должность, организацию и центр сертификации подписанта; для украинского КЕП: коды ЄДРПОУ и РНОКПП (РНОКПП хранится только маскированным).

**Доказательство:**

```text
Подписант: Іван Петренко
Организация: ТОВ Приклад
ЄДРПОУ: 12345678
Должность: Директор
E-mail: ivan.petrenko@example.com
РНОКПП: ********99
АЦСК: Example Test QTSP CA
Время подписи: 2026-11-22T01:06:56Z
Метка TSA: 2026-11-22T01:06:56Z
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_modified.pdf

**Рекомендация.** Учитывать, что подписанные документы раскрывают данные сертификата; для публикации использовать печать организации или отдельную публичную подпись.

*Происхождение: Правило doc.signer\_identity; Документы: signed\_modified.pdf*

### F-68 · Внешние источники данных в network.vsdx - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590 · Gather Victim Network Information

**Описание.** Подключения к базам данных, файлы .odc, сводные таблицы и внешние ссылки диаграмм раскрывают серверы, базы, учётные записи и пути к файлам.

**Доказательство:**

```text
visio:data.01.connection: Provider=SQLOLEDB;Data Source=SQL01.corp.example.test;Initial Catalog=Assets;Integrated Security=SSPI
visio:data.01.file: C:\Users\i.petrenko\Documents\assets.xlsx
```

**URL:** https://files.contoso.example/corpus/visio/network.vsdx

**Рекомендация.** Удалять подключения к данным и кэши сводных таблиц перед публикацией (вставлять значения).

*Происхождение: Правило doc.data\_connection; Документы: network.vsdx*

### F-69 · Серийный номер устройства в медиафайле (photo.heic) - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1592.001 · Gather Victim Host Information: Hardware

**Описание.** Видео или фото содержит серийный номер камеры/телефона: по нему связываются другие публикации с того же устройства.

**Доказательство:**

```text
EXAMPLE-BODY-0042
```

**URL:** https://files.contoso.example/corpus/media/photo.heic

**Рекомендация.** Удалять метаданные медиафайлов перед публикацией.

*Происхождение: Правило media.device\_serial; Документы: photo.heic*

### F-70 · Microsoft Office Word 2013 (EOL) у 2 документов - Средний

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 2 документа созданы в Microsoft Office Word 2013 (15), поддержка завершена 2023-04-11. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: Microsoft Office Word 2013 (15)
Документов: 2
```

**URL:** https://files.contoso.example/corpus/ooxml/contract.docx

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: contract.docx, report.pdf*

### F-71 · Раскрыты имена и логины 20 сотрудников - Средний

**Статус:** Новая · **Хост:** \- · **Категория:** people · **MITRE ATT&CK v20:** T1589.003 · Gather Victim Identity Information: Employee Names

**Описание.** Метаданные документов раскрывают 20 сотрудников (ФИО и логины). Это основа для целевого фишинга и подбора паролей.

**Доказательство:**

```text
john.doe - John Doe
i.petrenko - i.petrenko
ivan.petrenko - Іван Петренко
o.kovalenko - Olena Kovalenko
m.shevchuk - Марина Шевчук
a.bondar - Андрій Бондар
p.harvey - Phil Harvey
t.melnyk - Тетяна Мельник
```

**Рекомендация.** Очищать поля Author/LastModifiedBy при публикации; задать нейтральное имя автора в шаблонах.

*Происхождение: Правило mass-names*

### F-72 · Microsoft Excel 2010 (EOL) у 1 документа - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 1 документ создан в Microsoft Excel 2010 (14), поддержка завершена 2020-10-13. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: Microsoft Excel 2010 (14)
Документов: 1
Исторические данные (2023): документы из веб-архива или старше 3 лет, важность понижена
```

**URL:** https://files.contoso.example/corpus/ooxml/schedule.xlsx

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: schedule.xlsx*

### F-73 · Комментарии рецензентов сохранены в schedule.xlsx - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе сохранены режим рецензирования (0 исправлений, из них 0 удалений) и 2 комментария: видны прежние формулировки и внутренняя переписка.

**Доказательство:**

```text
комментарий v.tkachenko: «Ключ AWS тимчасовий»
комментарий s.lysenko: «ok»
```

**URL:** https://files.contoso.example/corpus/ooxml/schedule.xlsx

**Рекомендация.** Принимать все исправления и удалять комментарии перед публикацией; для внешних документов использовать PDF.

*Происхождение: Правило revisions; Документы: schedule.xlsx*

### F-74 · Adobe Photoshop 7.0 (EOL) у 3 документов - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 3 документа созданы в Adobe Photoshop 7.0, снято с поддержки. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: Adobe Photoshop 7.0
Документов: 3
Исторические данные (2005): документы из веб-архива или старше 3 лет, важность понижена
```

**URL:** https://files.contoso.example/corpus/real/exiftool-ExifTool.jpg

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: exiftool-ExifTool.jpg, exiftool-GPS.jpg, exiftool-PDF.pdf*

### F-75 · Внутренние адреса и имена хостов в документе (2) · budget.msg - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Текст или поля документа «budget.msg» раскрывают внутреннюю адресацию сети: 10.20.30.42, 10.20.0.15.

**Доказательство:**

```text
поле msg:internal_ips: [скрыто], 10.20.0.15
поле msg:internal_ips: 10.20.30.42, [скрыто]
```

**URL:** https://files.contoso.example/corpus/mail/budget.msg

**Рекомендация.** Удалять технические подробности (адреса, имена серверов) из публикуемых документов.

*Происхождение: Правило internal-addresses; Документы: budget.msg*

### F-76 · Комментарии рецензентов сохранены в report.pdf - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе сохранены режим рецензирования (0 исправлений, из них 0 удалений) и 1 комментарий: видны прежние формулировки и внутренняя переписка.

**Доказательство:**

```text
комментарий t.melnyk, 2024-03-15T09:00:00: «Перевірити суму»
```

**URL:** https://files.contoso.example/corpus/pdf/report.pdf

**Рекомендация.** Принимать все исправления и удалять комментарии перед публикацией; для внешних документов использовать PDF.

*Происхождение: Правило revisions; Документы: report.pdf*

### F-77 · Старые ревизии PDF сохранены в report.pdf - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** PDF сохранён инкрементально (1 обновл.), предыдущие версии метаданных и содержимого можно восстановить.

**Доказательство:**

```text
ревизия 1: Author: o.kovalenko; Company: Contoso Energy; Creator: Microsoft® Word 2013; Producer: Microsoft® Word 2013; Title: Річний звіт 2024
```

**URL:** https://files.contoso.example/corpus/pdf/report.pdf

**Рекомендация.** Пересохранять PDF полностью («Сохранить как» с оптимизацией) или очищать скрытые данные перед публикацией.

*Происхождение: Правило pdf-revisions; Документы: report.pdf*

### F-78 · Старые ревизии PDF сохранены в signed\_modified.pdf - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** PDF сохранён инкрементально (1 обновл.), предыдущие версии метаданных и содержимого можно восстановить.

**Доказательство:**

```text
ревизия 1: Author: Ivan Petrenko; Producer: FOCA-rs fixture
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_modified.pdf

**Рекомендация.** Пересохранять PDF полностью («Сохранить как» с оптимизацией) или очищать скрытые данные перед публикацией.

*Происхождение: Правило pdf-revisions; Документы: signed\_modified.pdf*

### F-79 · Комментарии рецензентов сохранены в strategy.pptx - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе сохранены режим рецензирования (0 исправлений, из них 0 удалений) и 1 комментарий: видны прежние формулировки и внутренняя переписка.

**Доказательство:**

```text
комментарий m.shevchuk, 2024-02-10T12:00:00: «Прибрати цифри EBITDA до публікації»
```

**URL:** https://files.contoso.example/corpus/ooxml/strategy.pptx

**Рекомендация.** Принимать все исправления и удалять комментарии перед публикацией; для внешних документов использовать PDF.

*Происхождение: Правило revisions; Документы: strategy.pptx*

### F-80 · Внутренние адреса и имена хостов в документе (1) · contract.docx - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Текст или поля документа «contract.docx» раскрывают внутреннюю адресацию сети: 10.10.1.5.

**Доказательство:**

```text
текст, строка 6: Доступ до порталу: Server=[скрыто];Database=tender;User Id=sa;Password=[скрыто]
```

**URL:** https://files.contoso.example/corpus/ooxml/contract.docx

**Рекомендация.** Удалять технические подробности (адреса, имена серверов) из публикуемых документов.

*Происхождение: Правило internal-addresses; Документы: contract.docx*

### F-81 · Внутренние пути и логины в метаданных 17 документов - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1592 · Gather Victim Host Information

**Описание.** Пути шаблонов, вложений и ссылок в 17 документах раскрывают логины сотрудников и структуру файловых ресурсов.

**Доказательство:**

```text
\\FS01.corp.example.test\finance$ by i.petrenko
C:\Users\ipetrenko\Documents\My Data Sources\srv-sql01 Payroll.odc
C:\Users\ipetrenko\Desktop\[budget.xlsx]Sheet1
\\SRV-FILE01\photo\TES2
\\SRV-FILE01\scan$\2023-11
C:\Users\m.shevchuk\Pictures\Screenshots\portal.png
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Очищать метаданные перед публикацией (Инспектор документов, exiftool), внедрить проверку в процесс публикации.

*Происхождение: Правило internal-paths; Документы: backup.zip, hidden.xlsx, photo.jpg, scan.tiff, screenshot.png, annual.indd, network.lnk, report.lnk, letter.odt, legacy.doc, contract.docx, schedule.xlsx, meeting.ics, SRV-TS01.rdp, buh.ica, logo.svg, network.vsdx*

### F-82 · Внутренние адреса и имена хостов в документе (1) · buh.ica - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Текст или поля документа «buh.ica» раскрывают внутреннюю адресацию сети: 10.10.1.40.

**Доказательство:**

```text
поле ica:1C Бухгалтерія.Address: [скрыто]:1494
```

**URL:** https://files.contoso.example/corpus/remote/buh.ica

**Рекомендация.** Удалять технические подробности (адреса, имена серверов) из публикуемых документов.

*Происхождение: Правило internal-addresses; Документы: buh.ica*

### F-83 · Устаревшая ОС Windows 7 / Server 2008 R2 у 1 документа - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1592.002 · Gather Victim Host Information: Software

**Описание.** Метаданные 1 документа указывают, что он создан в Windows 7 / Server 2008 R2: ОС без обновлений безопасности.

**Доказательство:**

```text
ОС: Windows 7 / Server 2008 R2
Документов: 1
Исторические данные (2019): документы из веб-архива или старше 3 лет, важность понижена
```

**URL:** https://files.contoso.example/corpus/ole/legacy.doc

**Рекомендация.** Вывести из эксплуатации или изолировать рабочие места с неподдерживаемой ОС.

*Происхождение: Правило eol-os; Документы: legacy.doc*

### F-84 · Устаревшая ОС Windows XP у 2 документов - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1592.002 · Gather Victim Host Information: Software

**Описание.** Метаданные 2 документов указывают, что они созданы в Windows XP: ОС без обновлений безопасности.

**Доказательство:**

```text
ОС: Windows XP
Документов: 2
Исторические данные (2008): документы из веб-архива или старше 3 лет, важность понижена
```

**URL:** https://files.contoso.example/corpus/real/poi-SampleDoc.doc

**Рекомендация.** Вывести из эксплуатации или изолировать рабочие места с неподдерживаемой ОС.

*Происхождение: Правило eol-os; Документы: poi-SampleDoc.doc, poi-SampleSS.xls*

### F-85 · Идентификатор арендатора Microsoft 365 в письме (budget.eml) - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Заголовки письма содержат идентификатор арендатора Microsoft 365 организации.

**Доказательство:**

```text
00000000-1111-2222-3333-444444444444
```

**URL:** https://files.contoso.example/corpus/mail/budget.eml

**Рекомендация.** Учитывать при оценке поверхности атаки облачной инфраструктуры.

*Происхождение: Правило mail.m365\_tenant; Документы: budget.eml*

### F-86 · Комментарии рецензентов сохранены в network.vsdx - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** В документе сохранены режим рецензирования (0 исправлений, из них 0 удалений) и 1 комментарий: видны прежние формулировки и внутренняя переписка.

**Доказательство:**

```text
комментарий ivan.petrenko, 2024-03-14T18:00:00: «Пароль адміна на стікері, прибрати»
```

**URL:** https://files.contoso.example/corpus/visio/network.vsdx

**Рекомендация.** Принимать все исправления и удалять комментарии перед публикацией; для внешних документов использовать PDF.

*Происхождение: Правило revisions; Документы: network.vsdx*

### F-87 · Внутренние адреса и имена хостов в документе (4) - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Текст или поля документа «backup.zip» раскрывают внутреннюю адресацию сети: 10.20.30.42, 10.20.0.15, 192.168.10.17, 10.20.0.16.

**Доказательство:**

```text
текст, строка 32: [скрыто], 10.20.0.15
текст, строка 32: 10.20.30.42, [скрыто]
текст, строка 52: [скрыто], 10.20.0.16
текст, строка 52: 192.168.10.17, [скрыто]
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Удалять технические подробности (адреса, имена серверов) из публикуемых документов.

*Происхождение: Правило internal-addresses; Документы: backup.zip*

### F-88 · Идентификатор арендатора Microsoft 365 в письме (backup.zip) - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Заголовки письма содержат идентификатор арендатора Microsoft 365 организации.

**Доказательство:**

```text
00000000-1111-2222-3333-444444444444
```

**URL:** https://files.contoso.example/corpus/archive/backup.zip

**Рекомендация.** Учитывать при оценке поверхности атаки облачной инфраструктуры.

*Происхождение: Правило mail.m365\_tenant; Документы: backup.zip*

### F-89 · Microsoft Word 2008 для Mac (EOL) у 1 документа - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 1 документ создан в Microsoft Word 2008 для Mac (12), поддержка завершена 2013-04-09. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: Microsoft Word 2008 для Mac (12)
Документов: 1
Исторические данные (2009): документы из веб-архива или старше 3 лет, важность понижена
```

**URL:** https://files.contoso.example/corpus/real/exiftool-OOXML.docx

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: exiftool-OOXML.docx*

### F-90 · Старые ревизии PDF сохранены в revisions.pdf - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** PDF сохранён инкрементально (1 обновл.), предыдущие версии метаданных и содержимого можно восстановить.

**Доказательство:**

```text
ревизия 1: Author: John Doe; Creator: Writer; Producer: FOCA-rs fixture
```

**URL:** https://files.contoso.example/corpus/forensics/revisions.pdf

**Рекомендация.** Пересохранять PDF полностью («Сохранить как» с оптимизацией) или очищать скрытые данные перед публикацией.

*Происхождение: Правило pdf-revisions; Документы: revisions.pdf*

### F-91 · Предыдущие версии метаданных сохранены в legacy.doc - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213 · Data from Information Repositories

**Описание.** Документ хранит историю сохранений (2 версии): прежние авторы и пути к файлам.

**Доказательство:**

```text
ревизия 1: 
ревизия 2: 
```

**URL:** https://files.contoso.example/corpus/ole/legacy.doc

**Рекомендация.** Пересохранять PDF полностью («Сохранить как» с оптимизацией) или очищать скрытые данные перед публикацией.

*Происхождение: Правило pdf-revisions; Документы: legacy.doc*

### F-92 · LibreOffice 7.2.5.2 (EOL) у 1 документа - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 1 документ создан в LibreOffice 7.2.5.2, поддержка завершена 2022-06-12. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: LibreOffice 7.2.5.2
Документов: 1
Исторические данные (2022): документы из веб-архива или старше 3 лет, важность понижена
```

**URL:** https://files.contoso.example/corpus/odf/letter.odt

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: letter.odt*

### F-93 · Внутренние адреса и имена хостов в документе (2) · budget.eml - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Текст или поля документа «budget.eml» раскрывают внутреннюю адресацию сети: 10.20.30.42, 10.20.0.15.

**Доказательство:**

```text
поле eml:internal_ips: [скрыто], 10.20.0.15
поле eml:internal_ips: 10.20.30.42, [скрыто]
```

**URL:** https://files.contoso.example/corpus/mail/budget.eml

**Рекомендация.** Удалять технические подробности (адреса, имена серверов) из публикуемых документов.

*Происхождение: Правило internal-addresses; Документы: budget.eml*

### F-94 · Имена 9 компьютеров и серверов внутренней сети - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590 · Gather Victim Network Information

**Описание.** Метаданные документов раскрывают NetBIOS-имена рабочих станций и серверов, что помогает спланировать атаку внутри сети.

**Доказательство:**

```text
ENG-WS11, SRV-FILE01, MFP-2F, BUH-PC-07, WS-042, NAS02, SRV-PRN01, SRV-SQL02, FS01
```

**URL:** https://files.contoso.example/corpus/images/photo.jpg

**Рекомендация.** Очищать метаданные перед публикацией; не использовать в именах ПК отдел и ФИО сотрудника.

*Происхождение: Правило internal-pcs; Документы: photo.jpg, scan.tiff, network.lnk, report.lnk, letter.odt, legacy.doc, contract.docx, schedule.xlsx, meeting.ics*

### F-95 · Время подписи и метка TSA расходятся более чем на сутки (signed\_hidden.docx) - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs

**Описание.** Заявленное время подписания заметно отличается от времени метки доверенного сервиса (TSA): часы подписанта неверны или дата подписи указана задним числом.

**Доказательство:**

```text
Подписант: John Doe
Организация: Example LLC
ЄДРПОУ: 87654321
Должность: Accountant
РНОКПП: ********99
АЦСК: Example Test QTSP CA
Время подписи: 2024-03-01T08:00:01Z
Метка TSA: 2026-11-22T01:06:57Z
```

**URL:** https://files.contoso.example/corpus/forensics/signed\_hidden.docx

**Рекомендация.** Проверить дату подписания по метке времени TSA.

*Происхождение: Правило doc.signature\_tsa\_gap; Документы: signed\_hidden.docx*

### F-96 · Параметры удалённого доступа раскрыты в файле SRV-TS01.rdp - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.002 · Gather Victim Network Information: DNS

**Описание.** Опубликованный файл подключения (RDP/ICA) содержит адрес сервера, шлюз и имя пользователя по умолчанию.

**Доказательство:**

```text
full address: SRV-TS01.corp.contoso.example:3389
username: CONTOSO\i.petrenko
gateway: rdgw.contoso.example
```

**URL:** https://files.contoso.example/corpus/remote/SRV-TS01.rdp

**Рекомендация.** Удалить файл с сайта, не публиковать служебные файлы конфигурации.

*Происхождение: Правило remote-file; Документы: SRV-TS01.rdp*

### F-97 · OpenOffice.org 3.2 (EOL) у 1 документа - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** sw · **MITRE ATT&CK v20:** T1203 · Exploitation for Client Execution

**Описание.** 1 документ создан в OpenOffice.org 3.2, поддержка завершена 2011-04-15. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.

**Доказательство:**

```text
Сигнатура: OpenOffice.org 3.2
Документов: 1
Исторические данные (2010): документы из веб-архива или старше 3 лет, важность понижена
```

**URL:** https://files.contoso.example/corpus/real/exiftool-OpenDoc.ods

**Рекомендация.** Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.

*Происхождение: Правило eol-software; Документы: exiftool-OpenDoc.ods*

### F-98 · Параметры удалённого доступа раскрыты в файле buh.ica - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.002 · Gather Victim Network Information: DNS

**Описание.** Опубликованный файл подключения (RDP/ICA) содержит адрес сервера, шлюз и имя пользователя по умолчанию.

**Доказательство:**

```text
full address: 10.10.1.40:1494
username: o.kovalenko
gateway: ctx.contoso.example:8080
```

**URL:** https://files.contoso.example/corpus/remote/buh.ica

**Рекомендация.** Удалить файл с сайта, не публиковать служебные файлы конфигурации.

*Происхождение: Правило remote-file; Документы: buh.ica*

### F-99 · Внутренние адреса и имена хостов в документе (1) · network.vsdx - Низкий

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1590.005 · Gather Victim Network Information: IP Addresses

**Описание.** Текст или поля документа «network.vsdx» раскрывают внутреннюю адресацию сети: 10.20.0.10.

**Доказательство:**

```text
текст, строка 1: DC01 [скрыто]
```

**URL:** https://files.contoso.example/corpus/visio/network.vsdx

**Рекомендация.** Удалять технические подробности (адреса, имена серверов) из публикуемых документов.

*Происхождение: Правило internal-addresses; Документы: network.vsdx*

### F-100 · Определён шаблон корпоративных e-mail: {f}.{last}@contoso.example - Инфо

**Статус:** Новая · **Хост:** contoso.example · **Категория:** people · **MITRE ATT&CK v20:** T1589.002 · Gather Victim Identity Information: Email Addresses

**Описание.** По 3 адресам из документов определён шаблон {f}.{last}@contoso.example (уверенность 100%). Это упрощает подготовку целевого фишинга.

**Доказательство:**

```text
Пример: i.petrenko@contoso.example
```

**Рекомендация.** Учесть в программе обучения сотрудников; включить DMARC p=reject и защиту от спуфинга.

*Происхождение: Правило email-pattern*

### F-101 · Ссылки на облачные пространства и URL с токенами в meeting.ics - Инфо

**Статус:** Новая · **Хост:** files.contoso.example · **Категория:** docs · **MITRE ATT&CK v20:** T1213.003 · Data from Information Repositories: Code Repositories

**Описание.** Документ ссылается на облачные рабочие пространства (Google Drive, SharePoint, Notion, Trello, Jira…) или содержит URL со встроенными токенами доступа (токены маскированы).

**Доказательство:**

```text
Онлайн-встреча: https://example.zoom.us/j/1234567890?pwd=EXAMPLE
Онлайн-встреча: https://teams.microsoft.com/l/meetup-join/
Онлайн-встреча: https://teams.microsoft.com/l/meetup-join/19%3ameeting_EXAMPLE%40thread.v2/0?context=%7b%7d
Онлайн-встреча: https://teams.microsoft.com/l/meetup-join/19%3ameeting_EXAMPLE%40thread.v2/0
```

**URL:** https://files.contoso.example/corpus/pim/meeting.ics

**Рекомендация.** Проверить права доступа по ссылкам, отозвать токены и SAS-ссылки, закрыть публичный доступ к рабочим пространствам.

*Происхождение: Правило doc.links; Документы: meeting.ics*

### F-102 · Служебные учётные записи в метаданных: Administrator, admin, author, scan, user name - Инфо

**Статус:** Новая · **Хост:** \- · **Категория:** people · **MITRE ATT&CK v20:** T1087 · Account Discovery

**Описание.** Документы созданы под общими учётными записями (Administrator, User…): возможна работа с правами администратора и общие пароли.

**Доказательство:**

```text
Administrator · документов: 2
admin · документов: 1
author · документов: 1
scan · документов: 1
user name · документов: 1
```

**Рекомендация.** Работать под персональными учётными записями без прав администратора.

*Происхождение: Правило service-accounts*

## Исправленные находки

| ID | Важность | Находка | Хост | Исправлено в скане |
| --- | --- | --- | --- | --- |
| F-103 | Высокий | Внутренние почтовые серверы и адреса в заголовках письма (budget.eml) | files.contoso.example | \- |

## Люди

| Логин | Имя | Роль | Компьютер | E-mail | Документов |
| --- | --- | --- | --- | --- | --- |
| john.doe | John Doe |  |  | john.doe@example.org | 14 |
| i.petrenko | i.petrenko |  |  | i.petrenko@contoso.example, i.petrenko@example.com | 13 |
| ivan.petrenko | Іван Петренко |  |  | ivan.petrenko@example.com | 12 |
| o.kovalenko | Olena Kovalenko |  |  | o.kovalenko@contoso.example, o.kovalenko@example.com | 9 |
| m.shevchuk | Марина Шевчук |  |  |  | 5 |
| a.bondar | Андрій Бондар |  |  |  | 3 |
| p.harvey | Phil Harvey |  |  |  | 3 |
| t.melnyk | Тетяна Мельник |  |  |  | 3 |
| v.tkachenko | Віктор Ткаченко |  | ENG-WS11 |  | 3 |
| n.burch | Nick Burch |  |  |  | 2 |
| s.lysenko | Сергій Лисенко |  |  | s.lysenko@contoso.example | 2 |
| administrator (служебная) | Administrator | Служебная учётная запись |  |  | 2 |
| hogwarts | Hogwarts |  |  |  | 1 |
| i.bird | Irving Bird |  |  |  | 1 |
| i.britton | Ian Britton |  |  |  | 1 |
| i.informatica | IDHW IDHW Informatica |  |  |  | 1 |
| i.petrenko-2 | Ігор Петренко | Рецензент |  |  | 1 |
| j.roe | Jane Roe |  |  |  | 1 |
| jeff | Jeff |  |  |  | 1 |
| m.example | Mallory Example |  |  |  | 1 |
| m.lambert | Mary Lambert |  |  |  | 1 |
| admin (служебная) | admin | Служебная учётная запись |  |  | 1 |
| author (служебная) | author | Служебная учётная запись |  |  | 1 |
| scan (служебная) | scan | Служебная учётная запись | MFP-2F |  | 1 |
| user.name (служебная) | user name | Служебная учётная запись |  |  | 1 |

### E-mail

| Адрес | Имя | Найден в документах |
| --- | --- | --- |
| 040000008200e00074c5b7101a82e0080000000012345@exchange.corp.example.tes |  | да |
| a1b2c3d4e5@exch01.corp.example.test |  | да |
| i.petrenko.private@example.net |  | да |
| i.petrenko@contoso.example | i.petrenko | да |
| i.petrenko@example.com | i.petrenko | да |
| inner-0001@exch02.corp.example.test |  | да |
| ivan.petrenko@example.com | Іван Петренко | да |
| john.doe@example.org | John Doe | да |
| o.kovalenko@contoso.example | Olena Kovalenko | да |
| o.kovalenko@example.com | Olena Kovalenko | да |
| s.lysenko@contoso.example | Сергій Лисенко | да |
| x@example.com |  | да |
| a.bondar@contoso.example | Андрій Бондар | нет |
| i.bird@contoso.example | Irving Bird | нет |
| i.britton@contoso.example | Ian Britton | нет |
| i.informatica@contoso.example | IDHW IDHW Informatica | нет |
| j.roe@contoso.example | Jane Roe | нет |
| m.example@contoso.example | Mallory Example | нет |
| m.lambert@contoso.example | Mary Lambert | нет |
| m.shevchuk@contoso.example | Марина Шевчук | нет |
| n.burch@contoso.example | Nick Burch | нет |
| p.harvey@contoso.example | Phil Harvey | нет |
| t.melnyk@contoso.example | Тетяна Мельник | нет |
| v.tkachenko@contoso.example | Віктор Ткаченко | нет |
| buh@example.com |  | да |

## Инфраструктура

### Хосты

| Хост | IP | Роль | Технологии | Внутренний | Скоуп |
| --- | --- | --- | --- | --- | --- |
| 198.51.100.25 | 198.51.100.25 | \- | \- | нет | вне скоупа |
| 203.0.113.10 | 203.0.113.10 | \- | \- | нет | в скоупе |
| contoso.example | \- | \- | \- | нет | в скоупе |
| ctx.contoso.example | \- | Citrix | Citrix ICA | нет | в скоупе |
| files.contoso.example | \- | Веб-сервер | \- | нет | в скоупе |
| mail.example.org | \- | Почта | \- | нет | вне скоупа |
| mx1.example.org | \- | Почта | \- | нет | вне скоупа |
| portal.contoso.example | \- | \- | \- | нет | в скоупе |
| rdgw.contoso.example | \- | Терминальный | RDP | нет | в скоупе |
| 10.10.1.40 | 10.10.1.40 | Citrix | Citrix ICA | да | исключён |
| 10.10.1.5 | 10.10.1.5 | Внутренний | \- | да | исключён |
| 10.20.0.10 | 10.20.0.10 | Внутренний | \- | да | вне скоупа |
| 10.20.0.15 | 10.20.0.15 | Внутренний | \- | да | вне скоупа |
| 10.20.0.16 | 10.20.0.16 | Внутренний | \- | да | вне скоупа |
| 10.20.30.42 | 10.20.30.42 | Внутренний | \- | да | вне скоупа |
| 192.168.10.17 | 192.168.10.17 | Внутренний | \- | да | вне скоупа |
| MFP-2F | \- | МФУ | \- | да | вне скоупа |
| NAS02 | \- | Хранилище | \- | да | вне скоупа |
| SRV-FILE01 | \- | Файловый (внутр.) | \- | да | вне скоупа |
| SRV-PRN01 | \- | Принт-сервер | \- | да | вне скоупа |
| SRV-SQL02 | \- | СУБД | \- | да | вне скоупа |
| exch01.corp.example.test | \- | Почта | \- | да | вне скоупа |
| fs01.corp.example.test | \- | Файловый (внутр.) | \- | да | вне скоупа |
| sql01.corp.example.test | \- | СУБД | \- | да | вне скоупа |
| srv-sql01.corp.example.com | \- | СУБД | \- | да | вне скоупа |
| srv-ts01.corp.contoso.example | \- | Терминальный | RDP | да | в скоупе |
| ws-042.corp.example.test | \- | Внутренний | \- | да | вне скоупа |

### Компьютеры и серверы

| Компьютер | Тип | Пользователи | Документов |
| --- | --- | --- | --- |
| SRV-FILE01 | server |  | 4 |
| NAS02 | server |  | 2 |
| BUH-PC-07 | ws |  | 1 |
| ENG-WS11 | ws | v.tkachenko | 1 |
| FS01 | server |  | 1 |
| MFP-2F | server | scan | 1 |
| SRV-PRN01 | server |  | 1 |
| SRV-SQL02 | server |  | 1 |
| WS-042 | ws |  | 1 |

### Программное обеспечение

| Программное обеспечение | Версия | EOL | CVE | Документов |
| --- | --- | --- | --- | --- |
| Adobe Photoshop 7.0 | 7.0 | EOL дата неизвестна | - | 3 |
| Microsoft Office Excel |  |  | - | 2 |
| Fujifilm (камера) |  |  | - | 2 |
| iOS 17.4 | 17.4 | EOL 15.09.2025 | - | 2 |
| Microsoft Office Outlook 2016-2024 / 365 | 16 |  | - | 2 |
| Microsoft Office PowerPoint |  |  | - | 2 |
| Adobe Photoshop CC 2019 | CC 2019 | EOL дата неизвестна | - | 2 |
| Microsoft Office Visio |  |  | - | 2 |
| Microsoft Office Word |  |  | - | 2 |
| Microsoft Office Word 2013 | 15 | EOL 11.04.2023 | - | 2 |
| Adobe Acrobat Pro XI | 11.0.23 | EOL 15.10.2017 | - | 1 |
| Samsung Galaxy (Android) |  |  | - | 1 |
| Apache OpenOffice 4.1.14 | 4.1.14 |  | - | 1 |
| Canon (камера) |  |  | - | 1 |
| Canon imageRUNNER 1.2 | 1.2 |  | - | 1 |
| Microsoft Excel 2010 | 14 | EOL 13.10.2020 | - | 1 |
| GraphicConverter |  |  | - | 1 |
| Greenshot 1.2.10 | 1.2.10 |  | - | 1 |
| Ghostscript 9.50 | 9.50 |  | - | 1 |
| Adobe InDesign 19.2 | 19.2 |  | - | 1 |
| Inkscape 1.1.2 | 1.1.2 |  | - | 1 |
| iOS 16.6 | 16.6 | EOL 16.09.2024 | - | 1 |
| Adobe Lightroom 13.2 | 13.2 |  | - | 1 |
| LibreOffice 7.2.5.2 | 7.2.5.2 | EOL 12.06.2022 | - | 1 |
| Microsoft PowerPoint для Mac |  |  | - | 1 |
| Microsoft Word 2008 для Mac | 12 | EOL 09.04.2013 | - | 1 |
| OpenOffice.org 3.2 | 3.2 | EOL 15.04.2011 | - | 1 |
| PDFCreator 3.2.0 | 3.2.0 |  | - | 1 |
| Microsoft Office PowerPoint 2016-2024 / 365 | 16 |  | - | 1 |
| Microsoft Office Publisher 2016-2024 / 365 | 16 |  | - | 1 |

### Пути

| Путь | Логин | Хост | Документов |
| --- | --- | --- | --- |
| C:\\Users\\i.petrenko\\Documents | i.petrenko |  | 3 |
| /home/mshevchuk/brand/texture.png | m.shevchuk |  | 1 |
| C:\\Program Files\\1cv8\\common\\1cestart.exe |  |  | 1 |
| C:\\Users\\i.petrenko\\Documents\\assets.xlsx | i.petrenko |  | 1 |
| C:\\Users\\i.petrenko\\Documents\\Звіт.docx | i.petrenko |  | 1 |
| C:\\Users\\ipetrenko\\Desktop\\\[budget.xlsx\]Sheet1 | i.petrenko |  | 1 |
| C:\\Users\\ipetrenko\\Documents\\My Data Sources\\srv-sql01 Payroll.odc | i.petrenko |  | 1 |
| C:\\Users\\m.shevchuk\\Desktop\\Презентації\\logo.png | m.shevchuk |  | 1 |
| C:\\Users\\m.shevchuk\\Pictures\\Screenshots\\portal.png | m.shevchuk |  | 1 |
| C:\\Users\\o.kovalenko\\AppData\\Local\\1C | o.kovalenko |  | 1 |
| C:\\Users\\o.kovalenko\\Documents\\Звіти\\2019\\Статут.doc | o.kovalenko |  | 1 |
| \\\\FS01.corp.example.test\\buh\$ |  | FS01.corp.example.test | 1 |
| \\\\FS01.corp.example.test\\buh\$\\Звіти\\2024\\Q1.xlsx |  | FS01.corp.example.test | 1 |
| \\\\FS01.corp.example.test\\design\\annual-2023\\report.indd |  | FS01.corp.example.test | 1 |
| \\\\FS01.corp.example.test\\finance\$ by i.petrenko |  | FS01.corp.example.test | 1 |
| \\\\FS01\\rooms |  | FS01 | 1 |
| \\\\SRV-FILE01\\photo\\TES2 |  | SRV-FILE01 | 1 |
| \\\\SRV-FILE01\\public\\Шаблони\\Статут.doc |  | SRV-FILE01 | 1 |
| \\\\SRV-FILE01\\public\\Шаблони\\Юридичний.dot |  | SRV-FILE01 | 1 |
| \\\\SRV-FILE01\\scan\$\\2023-11 |  | SRV-FILE01 | 1 |
| \\\\SRV-PRN01\\Canon C5535 2F |  | SRV-PRN01 | 1 |
| file:///C:\\Users\\a.bondar\\Documents\\Тендер\\Специфікація\_v2.xlsx | a.bondar |  | 1 |
| file:///\\\\FS01.corp.example.test\\it\\network.vsdx |  | FS01.corp.example.test | 1 |
| file:///\\\\NAS02\\finance\\Бюджет\_2024.xlsx |  | NAS02 | 1 |
| file:///\\\\NAS02\\hr\\Накази\\2022 |  | NAS02 | 1 |
| file:///\\\\SRV-FILE01\\public\\Шаблони\\Договір.dotx |  | SRV-FILE01 | 1 |
| file:///home/tmelnyk/Шаблони/Бланк.ott | t.melnyk |  | 1 |

## Документы

| \# | Файл | Автор | Программное обеспечение | Создан | Признаки |
| --- | --- | --- | --- | --- | --- |
| 1 | backup.zip |  |  | 14.03.2024 | path, secret |
| 2 | broken.zip |  |  | 14.03.2024 |  |
| 3 | hidden.xlsx | john.doe |  |  | path, forensic |
| 4 | personal.docx | o.kovalenko |  | 14.03.2024 | secret, pii |
| 5 | redacted.pdf |  |  |  | forensic |
| 6 | revisions.pdf | j.roe |  |  | forensic |
| 7 | scan.pdf |  |  |  | forensic |
| 8 | signed.pdf | ivan.petrenko |  | 01.03.2024 | forensic |
| 9 | signed\_hidden.docx | john.doe |  |  | forensic |
| 10 | signed\_modified.pdf | m.example |  |  | forensic |
| 11 | timestamp.pdf |  |  |  | forensic |
| 12 | photo.jpg | v.tkachenko | iOS 16.6 | 02.08.2024 | path, eol, gps |
| 13 | scan.tiff | scan | Canon imageRUNNER 1.2 |  | path |
| 14 | screenshot.png | m.shevchuk | Samsung Galaxy (Android) | 02.08.2024 | path, eol |
| 15 | annual.indd | o.kovalenko | Adobe InDesign 19.2 | 01.03.2024 | path |
| 16 | broken.indd |  |  |  |  |
| 17 | broken.wpd |  |  |  |  |
| 18 | budget.wks |  |  |  |  |
| 19 | budget.wpd |  |  |  |  |
| 20 | leaflet.pub | ivan.petrenko | Microsoft Office Publisher 2016-2024 / 365 | 01.03.2024 |  |
| 21 | letter.wps | ivan.petrenko |  | 01.03.2024 |  |
| 22 | network.vsd | ivan.petrenko | Microsoft Office Visio (версия неизвестна) | 01.03.2024 |  |
| 23 | broken-linkinfo.lnk |  |  | 01.03.2024 |  |
| 24 | broken-truncated.lnk |  |  | 01.03.2024 |  |
| 25 | network.lnk |  |  | 01.03.2024 | path |
| 26 | report.lnk |  |  | 01.03.2024 | path |
| 27 | broken-mime.eml | john.doe |  |  |  |
| 28 | broken.msg |  |  |  |  |
| 29 | budget.eml | ivan.petrenko | Microsoft Office Outlook 2016-2024 / 365 | 14.03.2024 | path, secret |
| 30 | budget.msg | ivan.petrenko | Microsoft Office Outlook 2016-2024 / 365 | 14.03.2024 | path, secret |
| 31 | broken-boxes.mp4 |  |  |  |  |
| 32 | broken-iloc.heic |  |  |  |  |
| 33 | iphone.mov |  | iOS 17.4 | 14.03.2024 | eol, gps |
| 34 | photo.heic | ivan.petrenko | iOS 17.4 | 14.03.2024 | eol, gps |
| 35 | survey.mp4 | john.doe |  | 14.03.2024 | gps |
| 36 | encrypted.ods | admin | Apache OpenOffice 4.1.14 | 01.02.2017 |  |
| 37 | letter.odt | t.melnyk | LibreOffice 7.2.5.2 | 17.05.2022 | path, eol, revisions |
| 38 | budget.xls | s.lysenko | Microsoft Office Excel (версия неизвестна) | 20.12.2018 |  |
| 39 | legacy.doc | o.kovalenko | Microsoft Office Word (версия неизвестна) | 11.02.2019 | path, secret, eol |
| 40 | slides.ppt | m.shevchuk | Microsoft PowerPoint для Mac (версия неизвестна) | 05.11.2019 |  |
| 41 | vbaProject.bin |  |  |  |  |
| 42 | contract.docx | a.bondar | Microsoft Office Word 2013 (15) | 01.03.2024 | path, secret, eol, revisions |
| 43 | schedule.xlsx | s.lysenko | Microsoft Excel 2010 (14) | 01.10.2023 | path, secret, eol, revisions |
| 44 | strategy.pptx | m.shevchuk | Microsoft Office PowerPoint 2016-2024 / 365 | 20.01.2024 | revisions |
| 45 | objstm.pdf | m.shevchuk | PDFCreator 3.2.0 | 05.01.2020 | secret |
| 46 | report.pdf | administrator | Microsoft Office Word 2013 (15) | 14.03.2024 | eol, revisions |
| 47 | broken.ics |  |  |  |  |
| 48 | broken.vcf |  |  |  |  |
| 49 | contacts.vcf |  |  |  | gps |
| 50 | meeting.ics |  |  | 14.03.2024 | path |
| 51 | exiftool-ExifTool.jpg | p.harvey | Fujifilm (камера) | 19.05.2001 | eol |
| 52 | exiftool-ExifTool.tif |  | Canon (камера) |  |  |
| 53 | exiftool-FlashPix.ppt | author | Microsoft Office PowerPoint (версия неизвестна) | 09.02.2007 |  |
| 54 | exiftool-GPS.jpg | i.britton | Fujifilm (камера) | 13.07.2002 | eol, gps |
| 55 | exiftool-OOXML.docx | jeff | Microsoft Word 2008 для Mac (12) | 24.10.2009 | eol |
| 56 | exiftool-OpenDoc.ods | i.informatica | OpenOffice.org 3.2 | 19.04.2010 | eol |
| 57 | exiftool-PDF.pdf | p.harvey | Adobe Photoshop 7.0 | 18.07.2005 | eol, forensic |
| 58 | exiftool-PDF2.pdf |  |  |  | forensic |
| 59 | exiftool-PNG.png | p.harvey |  |  |  |
| 60 | exiftool-XMP.svg | i.bird |  |  |  |
| 61 | poi-SampleDoc.doc | n.burch | Microsoft Office Word (версия неизвестна) | 04.01.2008 | eol |
| 62 | poi-SampleSS.xls | n.burch | Microsoft Office Excel (версия неизвестна) | 04.01.2008 | eol |
| 63 | poi-basic\_test\_ppt\_file.ppt | hogwarts | Microsoft Office PowerPoint (версия неизвестна) | 13.05.2005 | eol |
| 64 | SRV-TS01.rdp |  |  |  | path, secret |
| 65 | buh.ica |  |  |  | path, secret |
| 66 | logo.svg | m.shevchuk | Inkscape 1.1.2 |  | path |
| 67 | network.vsdx | ivan.petrenko | Microsoft Office Visio (версия неизвестна) | 10.03.2024 | path, secret, revisions |

### Форензика документов

#### Подписи и КЕП

| Документ | Находка | Критичность |
| --- | --- | --- |
| signed\_modified.pdf | Документ изменён после подписания (signed\_modified.pdf) | Высокий |
| signed.pdf | Данные подписанта (КЕП) в документе signed.pdf: Іван Петренко | Средний |
| signed\_hidden.docx | Данные подписанта (КЕП) в документе signed\_hidden.docx: John Doe | Средний |
| signed\_modified.pdf | Данные подписанта (КЕП) в документе signed\_modified.pdf: Іван Петренко | Средний |
| signed\_hidden.docx | Время подписи и метка TSA расходятся более чем на сутки (signed\_hidden.docx) | Низкий |

#### Скрытое содержимое, замазывание и ревизии

| Документ | Находка | Критичность |
| --- | --- | --- |
| redacted.pdf | Плохое замазывание: текст под закраской читается (redacted.pdf) | Критический |
| revisions.pdf | Удалённый текст восстанавливается из старых ревизий PDF (revisions.pdf) | Высокий |
| signed\_modified.pdf | Удалённый текст восстанавливается из старых ревизий PDF (signed\_modified.pdf) | Высокий |
| hidden.xlsx | Скрытый текст и скрытые строки/столбцы в hidden.xlsx | Высокий |
| signed\_hidden.docx | Скрытый текст и скрытые строки/столбцы в signed\_hidden.docx | Высокий |
| exiftool-PDF.pdf | Скан без текстового слоя: exiftool-PDF.pdf | Средний |
| scan.pdf | Скан без текстового слоя: scan.pdf | Средний |
| exiftool-PDF2.pdf | Скан без текстового слоя: exiftool-PDF2.pdf | Средний |
| signed\_modified.pdf | Разные авторы или программы в ревизиях PDF (signed\_modified.pdf) | Средний |
| report.pdf | Разные авторы или программы в ревизиях PDF (report.pdf) | Средний |
| revisions.pdf | Разные авторы или программы в ревизиях PDF (revisions.pdf) | Средний |

#### Ссылки на облачные пространства и токены

| Документ | Находка | Критичность |
| --- | --- | --- |
| personal.docx | Ссылки на облачные пространства и URL с токенами в personal.docx | Критический |
| meeting.ics | Ссылки на облачные пространства и URL с токенами в meeting.ics | Инфо |

#### Персональные данные (сводка)

*Значения персональных данных в отчёт не включаются: только типы и количество.*

| Документ | Тип данных | Количество | Критичность |
| --- | --- | --- | --- |
| personal.docx | Банковская карта | 1 | Высокий |
| personal.docx | РНОКПП (ІПН) | 1 | Высокий |
| personal.docx | IBAN | 1 | Высокий |
| personal.docx | Гриф ограничения доступа | 1 | Высокий |
| personal.docx | Паспорт | 1 | Высокий |

## Журнал запросов

- Всего запросов: **5**
- Пассивные (сторонние сервисы): 2
- К цели (активные): 2
- Заблокировано скоупом: 1
- Хосты цели: 3
- Сторонние сервисы (хосты): 2
- Период работ: 20.11.2026 12:00, 20.11.2026 12:00 (UTC)

| Модуль | Число |
| --- | --- |
| httpmap | 2 |
| crawler | 1 |
| crtsh | 1 |
| wayback | 1 |

### Запросы к цели

| Время | Метод | URL | Код | Размер / тип | Модуль | Ошибка |
| --- | --- | --- | --- | --- | --- | --- |
| 20.11.2026 12:00 | GET | https://www.contoso.example/docs/ | 200 | 2 КБ | crawler |  |
| 20.11.2026 12:00 | GET | https://portal.contoso.example/ | 200 | 2 КБ | httpmap |  |

### Заблокированные скоупом

| Время | Метод | URL | Код | Размер / тип | Модуль | Ошибка |
| --- | --- | --- | --- | --- | --- | --- |
| 20.11.2026 12:00 | GET | https://mail.contoso.example/owa/ |  |  | httpmap | out\_of\_scope |

## Приложения

### Методика

Пассивная разведка по открытым источникам: поиск опубликованных документов (веб-архивы, поисковые системы, обход сайта), извлечение метаданных, анализ авторов, ПО, путей, хостов и секретов; активные проверки: только по целям скоупа и при включённых активных проверках и подтверждённом разрешении владельца.

### Секрет

| Тип | Файл | Путь | Секрет |
| --- | --- | --- | --- |
| conn | contract.docx | текст, строка 6 | \[скрыто\] |
| pass | buh.ica | поле ica:1C Бухгалтерія.ClearPassword | \[скрыто\] |
| api | personal.docx | текст, строка 9 | \[скрыто\] |
| pass | legacy.doc | текст, строка 1 | \[скрыто\] |
| pass | schedule.xlsx | поле xl/connections.xml | \[скрыто\] |
| pass | objstm.pdf | текст, строка 1 | \[скрыто\] |
| pass | SRV-TS01.rdp | поле rdp:password 51 | \[скрыто\] |

### Сканы

| ID | Профиль | Начало | Окончание | Выход | Статус |
| --- | --- | --- | --- | --- | --- |
| s1 | Стандартный | 20.11.2026 11:40 | 20.11.2026 12:00 | Напрямую (реальный IP) | done |

### Параметры отчёта

- **Только подтверждённые:** нет
- **Важность от:** все
- **Только выбранные:** нет
- **Секреты:** скрыты

---
*Сформировано FOCA-rs 2.0.0-beta.4 · 20.11.2026*
