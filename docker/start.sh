#!/bin/bash

CHROME_ARGS="--headless \
--ignore-certificate-errors \
--user-agent=\"${USER_AGENT}\" \
--no-sandbox \
--remote-debugging-address=${DEBUG_ADDRESS} \
--remote-debugging-port=${DEBUG_PORT} \
--user-data-dir=${HOME} \
--window-size=1280,768 \
--disable-background-networking \
--disable-client-side-phishing-detection \
--disable-default-apps \
--disable-gpu \
--disable-hang-monitor \
--disable-popup-blocking \
--disable-prompt-on-repost \
--disable-sync \
--disable-web-resources \
--enable-automation \
--enable-logging \
-log-level=0 \
--metrics-recording-only \
--no-first-run \
--password-store=basic \
--test-type=webdriver \
--use-mock-keychain \
--disable-dev-shm-usage"

if [[ -v TOR ]]; then
    service tor start
    CHROME_ARGS="$CHROME_ARGS --proxy-server=socks5://127.0.0.1:9050"
fi

echo $CHROME_ARGS

if [ -n "$CHROME_OPTS" ]; then
    CHROME_ARGS="${CHROME_ARGS} ${CHROME_OPTS}"
fi

sh -c "/usr/bin/google-chrome $CHROME_ARGS"
