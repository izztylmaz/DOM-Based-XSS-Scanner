import jsbeautifier
from multiprocessing import Process


def find_vulnerabilities(js_document_as_string):
    def find_vulnerability(src, detected_logs, js_str):
        sinks = [
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "setImmediate",
            "execScript",
            "crypto.generateCRMFRequest",
            "ScriptElement.src",
            "ScriptElement.text",
            "ScriptElement.textContent",
            "ScriptElement.innerText",
            "anyTag.onEventName",
            "document.write",
            "document.writeln",
            ".innerHTML",
            "Range.createContextualFragment",
            "window.location"
        ]
        cnt = 0
        for line in js_str.splitlines():
            cnt += 1
            if src in line:
                detected_logs[str(cnt)] = line

    sources = {
        "document.URL": {
            "process": None,
            "detected": {},
        },
        "document.documentURI": {
            "process": None,
            "detected": {},
        },
        "document.URLUnencoded": {
            "process": None,
            "detected": {},
        },
        "document.baseURI": {
            "process": None,
            "detected": {},
        },
        "location": {
            "process": None,
            "detected": {},
        },
        "location.href": {
            "process": None,
            "detected": {},
        },
        "location.search": {
            "process": None,
            "detected": {},
        },
        "location.hash": {
            "process": None,
            "detected": {},
        },
        "location.pathname": {
            "process": None,
            "detected": {},
        },
        "document.cookie": {
            "process": None,
            "detected": {},
        },
        "document.referrer": {
            "process": None,
            "detected": {},
        },
        "window.name": {
            "process": None,
            "detected": {},
        },
        "history.pushState()": {
            "process": None,
            "detected": {},
        },
        "history.replaceState()": {
            "process": None,
            "detected": {},
        },
        "localStorage": {
            "process": None,
            "detected": {},
        },
        "sessionStorage": {
            "process": None,
            "detected": {},
        },
    }
    for source in sources:
        sources[source]["process"] = Process(target=find_vulnerability(source, sources[source]["detected"], js_document_as_string))
        sources[source]["process"].start()

    for source in sources:
        sources[source]["process"].join()

    for source in sources:
        print(sources[source]["detected"])


def main():
    parsed_file = jsbeautifier.beautify_file("script.js")
    find_vulnerabilities(parsed_file)

if __name__ == '__main__':
    main()
