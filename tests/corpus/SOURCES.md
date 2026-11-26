# Корпус эталонных документов (N-4)

Рядом с каждым файлом лежит `<имя>.expected.json`: ожидаемый результат `foca_meta::extract()`.
Тест: `cargo test -p foca-meta --test golden`. Обновить эталоны после осознанного изменения
парсера: `UPDATE_GOLDEN=1 cargo test -p foca-meta --test golden` и просмотреть diff.

Общий размер корпуса: ~0,5 МБ (лимит 5 МБ).

## Синтетические файлы (сгенерированы, данные вымышленные)

| Каталог | Файлы | Генератор |
|---|---|---|
| `ole/` | `legacy.doc`, `budget.xls`, `slides.ppt`, `vbaProject.bin` | `cargo run -p foca-meta --example make_ole_corpus -- tests/corpus` (крейт `cfb`) |
| `images/` | `photo.jpg` (EXIF+GPS+миниатюра другого цвета, XMP, IPTC, COM), `screenshot.png` (tEXt, iTXt XMP, eXIf), `scan.tiff` | `python3 tests/corpus/make_corpus.py` (stdlib + Pillow) |
| `ooxml/` | `contract.docx` (исправления, комментарии, RSID, шаблон UNC, гиперссылки, принтер, вложенное фото), `schedule.xlsx` (скрытые листы, комментарии, внешняя ссылка, connection string, VBA), `strategy.pptx` (авторы комментариев, заметки, PNG) | `make_corpus.py` |
| `odf/` | `letter.odt` (meta.xml, исправления, аннотация, шаблон, фото), `encrypted.ods` | `make_corpus.py` |
| `pdf/` | `report.pdf` (2 ревизии Info, XMP во Flate, JavaScript, вложение .rdp, аннотация), `objstm.pdf` (PDF 1.5: ObjStm + xref-поток) | `make_corpus.py` |
| `svg/`, `remote/` | `logo.svg` (Inkscape, RDF), `SRV-TS01.rdp` (UTF-16LE), `buh.ica` | `make_corpus.py` |
| `lnk/` | `report.lnk` (LinkInfo локальный путь, том, TrackerDataBlock: имя ПК и MAC), `network.lnk` (UNC), `broken-*` | `python3 tests/corpus/make_corpus_13.py` |
| `mail/` | `budget.eml` (цепочка Received с внутренними IP, X-Originating-IP, Reply-To, вложения docx и message/rfc822), `budget.msg` (X.500-отправитель, получатели, вложение и вложенное письмо), `broken-*` | `make_corpus_13.py`; `.msg` - `cargo run -p foca-meta --example make_ole_corpus_13 -- tests/corpus` |
| `pim/` | `meeting.ics` (организатор, участники, ссылки Teams/Zoom, UID-домен), `contacts.vcf` (2 карточки, фото с EXIF GPS), `broken.*` | `make_corpus_13.py` |
| `media/` | `survey.mp4` (©xyz, ilst, XMP uuid), `iphone.mov` (mdta-ключи, серийник), `photo.heic` (Exif/XMP-элементы), `broken-*` | `make_corpus_13.py` |
| `legacy/` | `annual.indd` (XMP), `budget.wpd`, `budget.wks` (Lotus BOF), `network.vsd`, `leaflet.pub`, `letter.wps`, `broken.*` | `make_corpus_13.py`; OLE: `make_ole_corpus_13` |
| `visio/`, `archive/` | `network.vsdx` (страницы, комментарий, подключение к SQL), `backup.zip` (docx, lnk, eml, вложенный zip, имя с `../`), `broken.zip` | `make_corpus_13.py` |

Синтетические файлы сверены с ExifTool 13.10 (`perl exiftool -a -G1 -s <файл>`): совпадают
автор, даты, GPS, миниатюра, ревизии Info PDF, SttbSavedBy и авторы комментариев Word.

## Реальные публичные файлы (`real/`)

| Файл | Источник | Лицензия |
|---|---|---|
| `exiftool-GPS.jpg`, `exiftool-ExifTool.jpg`, `exiftool-ExifTool.tif`, `exiftool-PNG.png`, `exiftool-OOXML.docx`, `exiftool-PDF.pdf`, `exiftool-PDF2.pdf`, `exiftool-XMP.svg`, `exiftool-OpenDoc.ods`, `exiftool-FlashPix.ppt` | Набор тестов ExifTool 13.10, `t/images/`: https://cpan.metacpan.org/authors/id/E/EX/EXIFTOOL/Image-ExifTool-13.10.tar.gz | «same terms as Perl itself» (Artistic License или GPL), совместимо с GPL-3.0 |
| `poi-SampleDoc.doc`, `poi-SampleSS.xls`, `poi-basic_test_ppt_file.ppt` | Apache POI `test-data/`: https://github.com/apache/poi/tree/trunk/test-data | Apache License 2.0 |
