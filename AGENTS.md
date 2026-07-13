# Project conventions

- When adding JavaScript behavior, write and validate the normal JavaScript implementation first.
- Then add the equivalent inline JavaScript to the HTML when the email payload requires it.
- Keep the HTML version behaviorally equivalent to the JavaScript version.
- For `save/mail-sidebar/style.css`, keep only selectors whose class names are used by `save/mail-sidebar/index.html`; regenerate the filtered CSS automatically when the markup changes.

## Mail sidebar class inventory

The reference markup is `save/mail-sidebar/index.html`. Preserve these class
names when extending the sidebar:

- Message item: `_lvv_w _lvv_z _lvv_x listItemDefaultBackground`
- Layout: `_lvv_A _lvv_B _lvv_E _lvv_G _lvv_H _lvv_J _lvv_K _lvv_L _lvv_M _lvv_N _lvv_O _lvv_P _lvv_Q _lvv_R _lvv_S _lvv_T _lvv_U _lvv_V _lvv_31 _lvv_41`
- Outlook controls: `o365button o365buttonLabel owaimg noMargin hidden flex`
- Highlighting: `lvHighlightAllClass lvHighlightFromClass lvHighlightSubjectClass`
- Triage controls: `__Microsoft_Owa_TriageShared_templates_cs_2 __Microsoft_Owa_TriageShared_templates_cs_3`
- Icons: `ms-Icon--at ms-Icon--attachment ms-Icon--flag ms-Icon--mailUnread ms-Icon--pinDown ms-Icon--pinLeft ms-Icon--shield ms-Icon--thumbUp ms-Icon--trash`
- Microsoft styling: `ms-bgc-ts ms-bg-color-white ms-border-color-neutralTertiaryAlt ms-fcl-np ms-fcl-ns-b ms-fcl-nt-b ms-fcl-tp ms-fcl-tp-b ms-font-color-neutralSecondary ms-font-l ms-font-m ms-font-s ms-font-weight-semilight ms-fwt-sb ms-fwt-sl ms-icon-font-size-14 ms-icon-font-size-16 ms-icon-font-size-17 ms-icon-tall-glyph`
- Other existing classes: `checkboxImage csimg image-clear1x1-gif listItemDefaultBackground owa-color-neutral-green-alt owa-color-neutral-orange wf-size-checkboxMultiselectSize`

## CVE-2026-42897 email payload

- Treat `CVE-2026-42897/save/email-body.js` as the canonical source for the email payload. Rebuild `CVE-2026-42897/save/email-body.html` with `CVE-2026-42897/scripts/build-email-body.ps1` after JavaScript changes.
- Do not recreate `CVE-2026-42897/email-body.html`; the root payload file is not used for this scenario.
- Preserve the generated payload alert and keep the Base64 chunk length at or below 140 characters and the maximum generated HTML line length at or below 314 characters.
- After payload changes, verify with `node --test tests/email-body.test.js`, `node --check save/email-body.js`, the build script, Base64 decode back to exact JavaScript source, and `git diff --check`.

### Fake Outlook mail state model

- Keep unread and active state independent: `data-is-unread` controls unread visuals, `aria-selected`/active state controls only the row background.
- Initial fake mail state is unread and inactive: show only the left blue accent, with no active background.
- First click keeps the mail unread and makes it active: show active background plus the left blue accent.
- First deactivation after activation marks the fake mail read: remove active background and the left blue accent.
- Later clicks on the read fake mail show only active background; the left blue accent must not return.
- Do not make the sender bold in unread state. Unread styling applies to subject and received time only.
- The right-side unread status icon is intentionally hidden. Do not reintroduce it when unread state changes.
- The displayed received time is dynamic at insertion time and represents Moscow time minus four hours, formatted like `9:54 AM`.

### Outlook sidebar markup pitfalls

- Do not add `_lvv_y` to the fake mail item; in the captured Outlook CSS it collapses the left accent via `._lvv_y ._lvv_A`.
- Use existing Outlook classes only. Do not add custom CSS for the fake sidebar item.
- The checkbox is the existing `_lvv_B` button. Add `_lvv_C` only while the item is hovered or active; remove it when the item is inactive and not hovered.
- Triage hover actions must be icon-only buttons. Do not place visible text inside the icon spans.
- Triage DOM order should be `pin`, `flag`, `read`, `delete`; because Outlook icons float right, this renders visually as delete, read, flag, pin.
- When the fake mail is clicked, suspend the currently active real mail row so there is no double active highlight, but restore it before real mail click handlers run so real row selection remains stable.
