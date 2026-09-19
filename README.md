# Stored XSS in itslearning Android app via unvalidated
# `browser_fallback_url` (intent:// → WebView.loadUrl)

- App: itslearning LMS mobile app (Android), `com.itslearning.itslearningintapp` v3.12
- Class: `itslearning.app.common.ActivityWebView` (in-app content WebView)
- Class: CWE-79 (stored XSS), mobile-WebView-specific
- Status: **sink CONFIRMED (static)**; end-to-end delivery UNCONFIRMED (needs account)

## Root cause
`ActivityWebView.createWebView()` sets `setJavaScriptEnabled(true)`,
`setJavaScriptCanOpenWindowsAutomatically(true)`, `setDomStorageEnabled(true)`,
`setAllowFileAccess(true)`. In `shouldOverrideUrlLoading`:

    if (string.startsWith("intent://")) {
        uri = Intent.parseUri(string, 1);                        // URI_INTENT_SCHEME
        stringExtra = uri.getStringExtra("browser_fallback_url");
        if (uri != null && stringExtra != null) {
            webView.loadUrl(stringExtra);                        // <-- no scheme check
            return true;
        }
    }

The `browser_fallback_url` value is fully attacker-controlled (it comes from the
`intent://` link) and is passed directly to `WebView.loadUrl()`. There is no
validation that it is http/https, so:

  * `browser_fallback_url=javascript:<code>` executes `<code>` in the context of
    the page currently loaded in the WebView (an authenticated itslearning page).
  * `browser_fallback_url=file:///...` loads local files (allowFileAccess=true).

There is no `addJavascriptInterface`/`@JavascriptInterface` in the app, so this is
not JS->native RCE; it is XSS in the authenticated web session rendered by the app.

## Delivery / trigger
`shouldOverrideUrlLoading` fires on navigation, i.e. when the victim taps a link
(or a page navigates) to an `intent://` URL inside the app's WebView. The WebView
renders itslearning web content (course pages, bulletins, messages, LTI, "open
resource" flows via SSO-converted URLs). If any of those content types lets a user
store an anchor whose href uses the `intent:` scheme, then:

  attacker (e.g. a student) stores:
    <a href="intent://x#Intent;scheme=https;
             S.browser_fallback_url=javascript:<payload>;end">open</a>
  victim (student / teacher / admin / parent) opens that content in the Android
  app and taps -> `loadUrl("javascript:<payload>")` runs in their authenticated
  session -> session/DOM theft, actions as the victim.

This is a mobile-specific stored XSS: the same stored link is inert in a desktop
browser (no such gadget) but executes in the app's WebView.

## Impact
JavaScript execution in the victim's authenticated itslearning session in the app:
read/modify the DOM, read cookies/tokens available to the page, perform actions as
the victim, pivot to account takeover. Victims include minors, teachers, and
admins. Severity is High **if** a stored-content field permits `intent:`-scheme
anchors; it drops to informational if all such content is sanitized to http/https.

## What must be confirmed with a test account (the only missing step)
1. Find a stored-content field rendered in `ActivityWebView` (bulletin, message,
   comment, course/LTI page) whose HTML sanitizer allows an `intent:` href.
2. Store payload #1 from payloads.txt; open as a second user in the Android app.
3. Confirm the alert / cookie-exfil fires. Use your own OOB host for #2.

## Remediation
- In `shouldOverrideUrlLoading`, allow only `http`/`https` (optionally `mailto`)
  for the `browser_fallback_url` before calling `loadUrl`; reject `javascript:`,
  `file:`, `content:`, `data:` and unknown schemes.
- Set `setAllowFileAccess(false)` unless required.
- Ensure server-side HTML sanitisation of user content strips non-web URL schemes
  in href/src (defence in depth).

## Files
- poc-webview-xss.html — HTML that delivers the gadget when rendered in the WebView
- payloads.txt — raw intent:// payloads to paste into a stored-content field
