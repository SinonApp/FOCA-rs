/*
 * Recommended ranges for manual numeric settings, kept in one place (Settings, the launch
 * wizard and the brute-force screen all read it through F.numField).
 *
 * Manual input is never capped by a recommendation: any whole number from `min` up is accepted
 * and saved as typed. `min` is a crash-safety invariant the core also applies (at least one
 * thread, one second, one host); `max` exists only for percentages. `zero` marks settings where
 * 0 means "no limit". Past `warn` (or below `low`) the field shows an inline warning; past
 * `risky`, or 0 with `zeroRisky`, saving asks for a one-time confirmation. Defaults live in the
 * core (foca-store settings.rs) and are unchanged. Engine side and docs: docs/API.md, "Limits of
 * manual values".
 */
(function () {
  const F = window.FOCA;
  // Largest number a field accepts: far beyond any real use, safe for JSON, JS and u64.
  const TYPE_MAX = 999999999;
  const L = {
    "net.threads": { min: 1, rec: [4, 8], warn: 16, risky: 32, msg: "limits.warn_threads" },
    "net.rps": {
      min: 0,
      zero: true,
      zeroRisky: true,
      rec: [5, 10],
      warn: 20,
      risky: 50,
      msg: "limits.warn_rps",
      msgZero: "limits.zero_rps",
    },
    "net.hosts_parallel": { min: 1, rec: [2, 4], warn: 8, risky: 16, msg: "limits.warn_hosts" },
    "net.timeout": {
      min: 1,
      rec: [15, 30],
      low: 5,
      warn: 120,
      msg: "limits.warn_timeout",
      msgLow: "limits.warn_timeout_low",
    },
    "net.retries": { min: 0, rec: [1, 3], warn: 5, msg: "limits.warn_retries" },
    "power.mob_limit": {
      min: 0,
      zero: true,
      zeroRisky: true,
      rec: [500, 3000],
      low: 100,
      msgLow: "limits.warn_mob_low",
      msgZero: "limits.zero_mob",
    },
    "power.batt": {
      min: 1,
      max: 100,
      rec: [15, 30],
      low: 5,
      warn: 50,
      msg: "limits.warn_batt_high",
      msgLow: "limits.warn_batt_low",
    },
    "fuzz.rate": {
      min: 0,
      zero: true,
      zeroRisky: true,
      rec: [3, 5],
      warn: 10,
      risky: 20,
      msg: "limits.warn_fuzz_rate",
      msgZero: "limits.zero_fuzz_rate",
    },
    "fuzz.max_requests": {
      min: 0,
      zero: true,
      rec: [2000, 5000],
      warn: 20000,
      msg: "limits.warn_fuzz_requests",
      msgZero: "limits.zero_fuzz_requests",
    },
    "fuzz.max_time_min": {
      min: 0,
      zero: true,
      rec: [15, 30],
      warn: 120,
      msg: "limits.warn_fuzz_time",
      msgZero: "limits.zero_fuzz_time",
    },
    "fuzz.max_hosts": {
      min: 0,
      zero: true,
      rec: [1, 3],
      warn: 10,
      msg: "limits.warn_fuzz_hosts",
      msgZero: "limits.zero_fuzz_hosts",
    },
    "scan.max_docs": {
      min: 0,
      zero: true,
      rec: [200, 1000],
      warn: 5000,
      msg: "limits.warn_docs",
      msgZero: "limits.zero_docs",
    },
    "scan.max_size_mb": {
      min: 0,
      zero: true,
      rec: [20, 100],
      warn: 500,
      msg: "limits.warn_size",
      msgZero: "limits.zero_size",
    },
    "scan.crawl_depth": { min: 1, rec: [3, 8], warn: 10, msg: "limits.warn_depth" },
    "crawl.max_depth": { min: 1, rec: [3, 8], warn: 10, msg: "limits.warn_crawl_depth" },
    "crawl.max_pages": {
      min: 1,
      rec: [500, 2000],
      low: 50,
      warn: 20000,
      risky: 100000,
      msg: "limits.warn_crawl_pages",
      msgLow: "limits.warn_crawl_pages_low",
    },
    "crawl.max_minutes": { min: 1, rec: [10, 30], warn: 240, msg: "limits.warn_crawl_minutes" },
    "crawl.max_rendered": { min: 0, rec: [10, 50], warn: 500, msg: "limits.warn_crawl_rendered" },
    "crawl.max_images": { min: 0, rec: [100, 500], warn: 5000, msg: "limits.warn_crawl_images" },
    "crawl.max_image_mb": { min: 1, rec: [100, 500], warn: 5000, msg: "limits.warn_crawl_image_mb" },
    "crawl.doc_link_depth": { min: 0, rec: [1, 2], warn: 5, msg: "limits.warn_crawl_doc_depth" },
    "ocr.max_pages": { min: 1, rec: [5, 30], warn: 50, msg: "limits.warn_ocr_pages" },
    "ocr.max_mb": { min: 1, rec: [5, 25], warn: 50, msg: "limits.warn_ocr_mb" },
  };
  const t = (k, p, fb) => (F.t ? F.t(k, p, fb) : fb);
  // RU fallbacks of the warnings (the dictionaries in locales/<lang>/ui/settings.json win).
  const RU = {
    "limits.warn_threads":
      "Больше {n} потоков: телефон греется, а сайты чаще блокируют параллельные запросы.",
    "limits.warn_rps":
      "Больше {n} запросов в секунду: многие сайты блокируют или ограничивают вас, а телефон греется.",
    "limits.zero_rps":
      "Без ограничения скорости: запросы идут так быстро, как позволяют сеть и потоки. Высокий риск блокировки.",
    "limits.warn_hosts":
      "Больше {n} хостов сразу: нужно много памяти и соединений, на слабом телефоне скан может замедлиться.",
    "limits.warn_timeout": "Больше {n} с: зависший сервер надолго задержит скан.",
    "limits.warn_timeout_low": "Меньше {n} с: медленные серверы и Tor не успеют ответить.",
    "limits.warn_retries": "Больше {n} повторов: лишняя нагрузка на сервер и долгий скан при обрывах.",
    "limits.warn_mob_low": "Меньше {n} МБ: скан встанет на паузу почти сразу.",
    "limits.zero_mob": "Без лимита: скан может израсходовать весь мобильный трафик.",
    "limits.warn_batt_low": "Ниже {n}%: телефон может выключиться посреди скана.",
    "limits.warn_batt_high": "Выше {n}%: без зарядки скан будет часто вставать на паузу.",
    "limits.warn_fuzz_rate":
      "Больше {n} запросов в секунду: сайт заказчика заметит нагрузку, а его защита может заблокировать ваш IP.",
    "limits.zero_fuzz_rate":
      "Без ограничения скорости: перебор нагружает сайт заказчика на полную, высокий риск блокировки.",
    "limits.warn_fuzz_requests": "Больше {n} запросов: перебор займёт часы и заметно нагрузит сайт.",
    "limits.zero_fuzz_requests": "Без бюджета: перебор остановится только по времени или вручную.",
    "limits.warn_fuzz_time": "Больше {n} мин: перебор надолго займёт телефон и сеть.",
    "limits.zero_fuzz_time":
      "Без ограничения времени: перебор остановится только по бюджету запросов или вручную.",
    "limits.warn_fuzz_hosts": "Больше {n} адресов: перебор растянется, нагрузка ляжет на многие сайты.",
    "limits.zero_fuzz_hosts": "Все веб-адреса скоупа: на большом скоупе перебор займёт очень много времени.",
    "limits.warn_docs": "Больше {n} документов: скачивание займёт часы и много места.",
    "limits.zero_docs": "Без лимита: скачивается всё найденное, это может занять часы и гигабайты.",
    "limits.warn_size": "Больше {n} МБ: такие файлы почти всегда видео или архивы, качаются долго.",
    "limits.zero_size":
      "Без лимита размера: качаются файлы любого размера, но файлы больше 200 МБ не разбираются.",
    "limits.warn_depth": "Глубже {n} уровней: краулер обходит много страниц, скан идёт дольше.",
    "limits.warn_crawl_depth": "Глубже {n} уровней: обход уходит в архивы и фильтры, скан идёт дольше.",
    "limits.warn_crawl_pages": "Больше {n} страниц: обход займёт часы и заметно нагрузит сайт.",
    "limits.warn_crawl_pages_low": "Меньше {n} страниц: обход почти ничего не найдёт.",
    "limits.warn_crawl_minutes": "Больше {n} мин: обход надолго займёт телефон и сеть.",
    "limits.warn_crawl_rendered": "Больше {n} страниц через браузер: это медленно и расходует батарею.",
    "limits.warn_crawl_images": "Больше {n} изображений: много трафика и места.",
    "limits.warn_crawl_image_mb": "Больше {n} МБ на изображения: проверьте лимит мобильного трафика.",
    "limits.warn_crawl_doc_depth": "Глубже {n} шагов: ссылки из документов уводят далеко от цели.",
    "limits.warn_ocr_pages": "Больше {n} страниц: OCR долго нагружает процессор и батарею.",
    "limits.warn_ocr_mb": "Больше {n} МБ: OCR больших файлов медленный и требует много памяти.",
  };
  const say = (k, n) => t(k, { n }, (RU[k] || "").replace("{n}", n));
  /** Warning text for `value` of setting `key`, or "" when the value is within the recommendation. */
  const warning = (key, value) => {
    const d = L[key];
    if (!d || !Number.isFinite(value)) return "";
    if (d.zero && value === 0) return d.msgZero ? say(d.msgZero) : "";
    if (d.low != null && value < d.low && d.msgLow) return say(d.msgLow, d.low);
    if (d.warn != null && value > d.warn && d.msg) return say(d.msg, d.warn);
    return "";
  };
  /** `true` when saving `value` needs the one-time confirmation (`ctx.zeroRisky` can override). */
  const risky = (key, value, ctx = {}) => {
    const d = L[key];
    if (!d || !Number.isFinite(value)) return false;
    if (value === 0 && d.zero) return ctx.zeroRisky ?? !!d.zeroRisky;
    return d.risky != null && value > d.risky;
  };
  F.limits = { TYPE_MAX, all: L, get: key => L[key], warning, risky };
})();
