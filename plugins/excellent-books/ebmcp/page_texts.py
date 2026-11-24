"""Local approval copy. Every page follows the browser's Accept-Language (language_from_header);
English is default.

Customer words only: no protocol, program or field names (review 2026-11-17). The Estonian is
Teie (Task 53; buttons stay one-word commands); Kaupo reads it before release.
"""

from . import claims as _claims
from . import privacy as _privacy

DEFAULT_LANGUAGE = "en"

# Hosted-only copy, per language in HOSTED_TEXTS below. What the AI reads (a tool's "why") stays
# English (hosted_text(key) with no language); the pages follow Accept-Language (hosted_copy).
_HOSTED_EN = {
    "gone": (
        "This change is no longer waiting. It may have expired, been declined, or been lost "
        "when the service restarted. If you pressed Approve, check Excellent Books before "
        "asking the assistant to prepare it again."
    ),
    "hosted_inbox": "Changes waiting for your review",
    "hosted_empty": "No previews are waiting for your approval.",
    "hosted_signin": "Sign in to Excellent Books to review changes in this browser.",
    # One answer for every sign-in failure (opus review of 45d, S3): it never says which part
    # was wrong, and it never claims the change is gone.
    "hosted_signin_failed": (
        "The sign-in did not open this change. Check the server, company, Books user and "
        "password, and try again. If it still does not open, the change has ended: it expired, "
        "was declined, or was lost when the service restarted. If you pressed Approve just "
        "before, look in Excellent Books first; otherwise ask the assistant to prepare it again."
    ),
    "hosted_signin_busy": "Too many sign-in attempts. Try again in a few minutes.",
    "hosted_client": "AI app (as the app names itself)",
    "hosted_client_unknown": "No app name given",
    "hosted_signin_time": "Signed in at",
    "hosted_preview_until": "Preview valid until",
    "hosted_approval_until": "Approval valid until",
    "hosted_approved": "Approved. Go back to the chat to continue.",
    "hosted_approval_expired": "The approval expired. Nothing was written. Make a new preview.",
    # Opus review of 45f, N6: a restart loses every plan, so it says to prepare it again.
    "hosted_draining": "The service is restarting. If you already approved this change, check "
                       "Excellent Books first. When the service is back, sign in again and ask "
                       "the assistant to prepare the change again.",
    "hosted_audit_unavailable": "The write audit is unavailable. Ask the assistant to prepare "
                                "this change again before approving it.",
    "hosted_audit_notice": "Excellent keeps a write audit trail for up to 90 days, including the "
                           "document number. The preview stays in memory.",
}

# Task 53, Teie. Checked with the Estonian NLP tools 2026-11-19 (spelling, object case,
# officialese, compounds); only Excellent's own names were flagged. Kaupo reads it before release.
_HOSTED_ET = {
    "gone": (
        "See muudatus ei oota enam kinnitamist. Võib-olla see aegus, sellest keelduti või see "
        "kadus teenuse taaskäivitamisel. Kui vajutasite Kinnita, kontrollige enne Excellent "
        "Booksist, kas muudatus on tehtud, ja alles siis paluge tehisintellektil see uuesti ette "
        "valmistada."
    ),
    "hosted_inbox": "Teie kinnitust ootavad muudatused",
    "hosted_empty": "Ühtegi eelvaadet ei oota Teie kinnitust.",
    "hosted_signin": "Muudatuste ülevaatamiseks selles brauseris logige Excellent Booksi sisse.",
    "hosted_signin_failed": (
        "Sisselogimine ei avanud seda muudatust. Kontrollige serverit, ettevõtet, Booksi "
        "kasutajat ja parooli ning proovige uuesti. Kui muudatus ikka ei avane, on see lõppenud: "
        "see aegus, sellest keelduti või see kadus teenuse taaskäivitamisel. Kui vajutasite "
        "vahetult enne Kinnita, vaadake kõigepealt Excellent Booksist järele; muul juhul paluge "
        "tehisintellektil see uuesti ette valmistada."
    ),
    "hosted_signin_busy": "Sisselogimiskatseid on liiga palju. Proovige mõne minuti pärast uuesti.",
    "hosted_client": "Tehisintellekti rakendus (rakenduse enda antud nimi)",
    "hosted_client_unknown": "Rakendus ei andnud oma nime",
    "hosted_signin_time": "Sisse logitud",
    "hosted_preview_until": "Eelvaade kehtib kuni",
    "hosted_approval_until": "Kinnitus kehtib kuni",
    "hosted_approved": "Kinnitatud. Jätkamiseks minge tagasi vestlusse.",
    "hosted_approval_expired": "Kinnitus aegus. Midagi ei salvestatud. Koostage uus eelvaade.",
    "hosted_draining": "Teenus taaskäivitub. Kui olete selle muudatuse juba kinnitanud, "
                       "kontrollige kõigepealt Excellent Booksi. Kui teenus töötab jälle, logige "
                       "uuesti sisse ja paluge tehisintellektil muudatus uuesti ette valmistada.",
    "hosted_audit_unavailable": "Salvestatud muudatuste auditijälg ei ole kättesaadav. Enne "
                                "kinnitamist paluge tehisintellektil see muudatus uuesti ette "
                                "valmistada.",
    "hosted_audit_notice": "Excellent hoiab salvestatud muudatuste auditijälge kuni 90 päeva, "
                           "koos dokumendi numbriga. Eelvaadet hoitakse mälus.",
}

HOSTED_TEXTS = {"en": _HOSTED_EN, "et": _HOSTED_ET}

TEXTS = {
    "en": {
        "title": "Review the change before saving",
        "server": "Server",
        "company": "Company",
        "books_user": "Books user",
        "target": "Target",
        "operation": "Operation",
        "fields": "Fields and document preview",
        "col_field": "Field",
        "col_before": "Before",
        "col_after": "After",
        "col_value": "Value",
        "lines": "Lines",
        "line": "Line",
        "new_line": "new line",
        "chat_register": "Register",
        "chat_record": "Record",
        "chat_new_record": "new record",
        "chat_code": "Approval code",
        "details": "Other details",
        "document_now": "The document as it is now (open to see every field and line)",
        "line_now": "The whole line as it is now",
        "warning": "Warning",
        "result": "Result",
        "ledger": "Approval acknowledgement",
        "ack": "I understand what approving this does and that it cannot be undone here",
        "ack_required": "Please acknowledge the warning before approving.",
        "ledger_payment": "Payment acknowledgement",
        "ack_payment": "I understand this changes a payment and cannot be undone here",
        "ack_required_payment": "Please acknowledge the payment warning before approving.",
        "unfinished_write": (
            "The earlier write of {description} to {register} at {time} may not have finished. "
            "Check it in Excellent Books before you approve."
        ),
        "unfinished_description_unknown": "an unknown change",
        "unfinished_description_goods_receipt_one": "a goods receipt, {count} line",
        "unfinished_description_goods_receipt_many": "a goods receipt, {count} lines",
        "unfinished_description_items_one": "an item batch, {count} write",
        "unfinished_description_items_many": "an item batch, {count} writes",
        "unfinished_description_contacts_one": "a contact batch, {count} write",
        "unfinished_description_contacts_many": "a contact batch, {count} writes",
        "unfinished_description_record_change_one": "a record change, {count} write",
        "unfinished_description_record_change_many": "a record change, {count} writes",
        "unfinished_register_unknown": "an unknown register",
        "unfinished_time_unknown": "an unknown time",
        "unfinished_checked": "I checked Excellent Books",
        "unfinished_required": "Check Excellent Books and tick the box before approving.",
        "unfinished_unavailable": "The warning could not be cleared. If the earlier change is "
                                  "still being saved, wait for it to finish.",
        "approve": "Approve",
        "decline": "Decline",
        "decline_all": "Decline all",
        "queued": "Queued previews",
        "expired": "The preview expired. Make a new preview before approving.",
        "declined": "Declined. This preview will not be applied.",
        "approved": "Approved. Saving the change...",
        "done": "Done. The result is shown below.",
        "executing": "This preview is being applied. Check the result in the chat.",
        "error": "The request could not be accepted.",
        "connection_changed": ("This preview belongs to another Books connection than the one "
                               "saved now. Nothing was saved. Ask the AI to prepare it again."),
        "connection_changed_result": ("This change belongs to another Books connection than the "
                                      "one saved now. Check its result in the chat."),
        "settings_unreadable": ("The connection settings could not be read just now, so no "
                                "details are shown and nothing new is started. Reload this page "
                                "in a moment."),
        "consent_needed": ("Consent to share this data is switched off for this Books connection, "
                           "so no details are shown. Switch it on in the connection settings, "
                           "then reload this page."),
        "race_gap": (
            "If someone changes the same document in Books at the very moment it is saved, "
            "that cannot be prevented. You will be told after saving."
        ),
        "signin_title": "Sign in to Excellent Books",
        "signin_address": "Excellent Books server address",
        "signin_password": "Password",
        "signin_gdpr_tick": "I agree to share personal data with my AI service",
        "signin_hr_tick": "I also agree to share HR and payroll data with my AI service",
        "signin_writes_tick": ("The AI may prepare changes; each one waits for my approval on "
                               "this site"),
        "signin_submit": "Sign in",
        "signin_invalid": "Please start the sign-in again from your AI service.",
        "signin_address_refused": "This server address is not on the list.",
        "signin_unreachable": "We cannot reach the Excellent Books server.",
        "signin_credentials_refused": "Excellent Books refused the user or password.",
        "signin_gdpr_required": "Please tick the personal data box.",
        "signin_company_invalid": "Enter a company number greater than zero.",
        "signin_limited": "There have been too many sign-in attempts. Please try again later.",
        "signin_busy": "Sign-in is busy. Please try again later.",
        "signin_in_progress": "Sign-in is already in progress.",
        "signin_unavailable": "Sign-in is unavailable right now. Please try again later.",
        # The consent page (Task 27). The four HR points come from privacy.HR_POINTS below.
        "consent_title_hr": "HR and payroll data",
        "consent_title_gdpr": "Personal data",
        "consent_hr_intro": ("This AI connection reads HR and payroll data only if you say yes "
                             "here. Read these four points first."),
        # Only Claude Desktop opens this page for GDPR: it shows the Desktop text of privacy.py
        # (Task 50; spec 2026-11-16 section 6.2: the page renders the privacy constants), and the
        # hash of what it shows is what consent.record keeps.
        "consent_gdpr_text": _privacy.gdpr_text("desktop"),
        "consent_gdpr_lang": "en",       # the language consent_gdpr_text is in
        "consent_on": "Consent is on.",
        "consent_off": "Consent is off.",
        "consent_switch_on": "Switch on",
        "consent_switch_off": "Switch off",
        "consent_not_now": "Not now",
        "consent_close": "You can close this window.",
        "consent_error": "The consent could not be saved or read. Reload this page to see its state.",
    },
    "et": {
        "title": "Vaadake muudatus enne salvestamist üle",
        "server": "Server",
        "company": "Ettevõte",
        "books_user": "Booksi kasutaja",
        "target": "Muudetav kirje",
        "operation": "Toiming",
        "fields": "Väljad ja dokumendi eelvaade",
        "col_field": "Väli",
        "col_before": "Enne",
        "col_after": "Pärast",
        "col_value": "Väärtus",
        "lines": "Read",
        "line": "Rida",
        "new_line": "uus rida",
        "chat_register": "Register",
        "chat_record": "Kirje",
        "chat_new_record": "uus kirje",
        "chat_code": "Kinnituskood",
        "details": "Muud andmed",
        "document_now": "Dokument praegu (avage, et näha kõiki välju ja ridu)",
        "line_now": "Kogu rida praegu",
        "warning": "Hoiatus",
        "result": "Tulemus",
        "ledger": "Kinnitamise hoiatus",
        "ack": "Mõistan, mida kinnitamine teeb, ja et seda ei saa siin tagasi võtta",
        "ack_required": "Enne kinnitamist märkige, et mõistate hoiatust.",
        "ledger_payment": "Makse kinnitus",
        "ack_payment": "Mõistan, et see muudab makset ja seda ei saa siin tagasi võtta",
        "ack_required_payment": "Enne kinnitamist märkige, et mõistate makset puudutavat hoiatust.",
        "unfinished_write": (
            "Varasem salvestamine võis jääda pooleli ({description}, register {register}, "
            "aeg {time}). Kontrollige seda enne kinnitamist Excellent Booksis."
        ),
        "unfinished_description_unknown": "tundmatu muudatus",
        "unfinished_description_goods_receipt_one": "laosissetulek, {count} rida",
        "unfinished_description_goods_receipt_many": "laosissetulek, {count} rida",
        "unfinished_description_items_one": "artiklite partii, {count} salvestamine",
        "unfinished_description_items_many": "artiklite partii, {count} salvestamist",
        "unfinished_description_contacts_one": "kontaktide partii, {count} salvestamine",
        "unfinished_description_contacts_many": "kontaktide partii, {count} salvestamist",
        "unfinished_description_record_change_one": "kirje muudatus, {count} salvestamine",
        "unfinished_description_record_change_many": "kirje muudatus, {count} salvestamist",
        "unfinished_register_unknown": "teadmata",
        "unfinished_time_unknown": "teadmata",
        "unfinished_checked": "Kontrollisin Excellent Booksis",
        "unfinished_required": "Enne kinnitamist kontrollige Excellent Booksis ja märkige ruut.",
        "unfinished_unavailable": "Hoiatust ei õnnestunud eemaldada. Kui varasemat muudatust "
                                  "veel salvestatakse, oodake salvestamise lõppu.",
        "approve": "Kinnita",
        "decline": "Keeldu",
        "decline_all": "Keeldu kõigist",
        "queued": "Ootel eelvaated",
        "expired": "Eelvaade aegus. Enne kinnitamist koostage uus eelvaade.",
        "declined": "Keeldutud. Seda eelvaadet ei rakendata.",
        "approved": "Kinnitatud. Muudatust salvestatakse...",
        "done": "Valmis. Tulemus on allpool.",
        "executing": "Seda eelvaadet rakendatakse. Tulemust näete vestluses.",
        "error": "Päringut ei saanud vastu võtta.",
        "connection_changed": ("See eelvaade kuulub teisele Booksi ühendusele kui praegu "
                               "salvestatud ühendus. Midagi ei salvestatud. Paluge "
                               "tehisintellektil see uuesti koostada."),
        "connection_changed_result": ("See muudatus kuulub teisele Booksi ühendusele kui praegu "
                                      "salvestatud ühendus. Tulemust näete vestluses."),
        "settings_unreadable": ("Ühenduse seadeid ei õnnestunud praegu lugeda, seega ei näidata "
                                "siin üksikasju ega alustata midagi uut. Laadige leht hetke pärast "
                                "uuesti."),
        "consent_needed": ("Selle Booksi ühenduse andmete jagamise nõusolek on välja lülitatud, "
                           "seega ei näidata siin üksikasju. Lülitage nõusolek ühenduse seadetes "
                           "sisse ja laadige leht uuesti."),
        "race_gap": (
            "Kui keegi muudab sama dokumenti Booksis täpselt salvestamise hetkel, ei saa seda "
            "ära hoida. Sellest antakse teada pärast salvestamist."
        ),
        "signin_title": "Logige Excellent Booksi sisse",
        "signin_address": "Excellent Booksi serveri aadress",
        "signin_password": "Parool",
        "signin_gdpr_tick": "Nõustun isikuandmete jagamisega oma tehisintellekti teenusega",
        "signin_hr_tick": "Nõustun ka personali- ja palgaandmete jagamisega oma "
                          "tehisintellekti teenusega",
        "signin_writes_tick": ("Luban tehisintellekti teenusel muudatusi ette valmistada; iga "
                               "muudatus ootab minu kinnitust sellel veebilehel"),
        "signin_submit": "Logige sisse",
        "signin_invalid": "Palun alustage sisselogimist uuesti oma tehisintellekti teenusest.",
        "signin_address_refused": "Seda serveri aadressi ei ole lubatud aadresside loendis.",
        "signin_unreachable": "Excellent Booksi serveriga ei õnnestu ühendust saada.",
        "signin_credentials_refused": "Excellent Books ei aktsepteerinud kasutajat või parooli.",
        "signin_gdpr_required": "Palun märkige isikuandmete märkeruut.",
        "signin_company_invalid": "Sisestage nullist suurem ettevõtte number.",
        "signin_limited": "Sisselogimiskatseid on olnud liiga palju. Palun proovige hiljem uuesti.",
        "signin_busy": "Server on praegu hõivatud. Palun proovige hiljem uuesti.",
        "signin_in_progress": "Sisselogimine on juba pooleli.",
        "signin_unavailable": "Sisselogimine ei ole praegu saadaval. Palun proovige hiljem uuesti.",
        # Checked with the Estonian NLP spell-checker 2026-11-18 (only the product name flagged);
        # Kaupo reviews it in Task 53.
        "consent_title_hr": "Personali- ja palgaandmed",
        "consent_title_gdpr": "Isikuandmed",
        "consent_hr_intro": ("See tehisintellekti ühendus loeb personali- ja palgaandmeid ainult "
                             "siis, kui Te siin nõustute. Palun lugege enne läbi need neli punkti."),
        "consent_hr_1_head": "Andmekaitse",
        "consent_hr_1_body": (
            "personali- ja palgaandmetega vastustes on töötajate isikuandmed: nimed, isikukoodid, "
            "töötasud, pangakontod ja puudumised. Haigusleht ja muud puudumised võivad olla "
            "terviseandmed ehk isikuandmete eriliik isikuandmete kaitse üldmääruse artikli 9 "
            "tähenduses."),
        "consent_hr_2_head": "Isikuandmete kaitse üldmäärus",
        "consent_hr_2_body": (
            "need andmed saadetakse tehisintellekti teenusele, millega see ühendus on seotud. "
            "Vastutav töötleja on Teie ettevõte: selleks on vaja õiguslikku alust "
            "(terviseandmete puhul ka artikli 9 lõikes 2 nimetatud erandit) ja lepingut selle "
            "teenusega. Kontrollige, kus teenus andmeid töötleb, ja saatke ainult seda, mida "
            "küsimus vajab."),
        "consent_hr_3_head": "ELi tehisintellekti määrus",
        "consent_hr_3_body": (
            "kui tehisintellekti abil tehakse või toetatakse otsuseid töölevõtmise, edutamise, "
            "töölt vabastamise, töötasu või muude töötingimuste kohta, jagatakse ülesandeid "
            "käitumise või isikuomaduste järgi või hinnatakse töötajate tööd, võib see olla ELi "
            "tehisintellekti määruse III lisa järgi suure riskiga kasutus, millega kaasnevad Teie "
            "ettevõttele kohustused. Ärge tehke sellist otsust nende vastuste põhjal enne, kui "
            "inimene on selle üle vaadanud."),
        "consent_hr_4_head": "Täpsus",
        "consent_hr_4_body": ("tehisintellekt võib eksida. Kontrollige andmed Excellent Booksis "
                              "üle enne, kui nende põhjal midagi otsustate."),
        # Sol review of 849e1ca, MUST-FIX 1: the Estonian wording from before Task 50 said
        # Excellent does not see the data; it is not current. Task 53: the page shows the Estonian
        # Desktop text of privacy.py, and a yes here records ITS hash (consent.current_hashes
        # covers every page language; the English stopgap stays current on the English page).
        "consent_gdpr_text": _privacy.gdpr_text("desktop", "et"),
        "consent_gdpr_lang": "et",
        "consent_on": "Nõusolek on antud.",
        "consent_off": "Nõusolekut ei ole antud.",
        "consent_switch_on": "Lülita sisse",
        "consent_switch_off": "Lülita välja",
        "consent_not_now": "Mitte praegu",
        "consent_close": "Võite selle akna sulgeda.",
        "consent_error": ("Nõusolekut ei õnnestunud salvestada ega lugeda. Laadige leht uuesti, "
                          "et näha nõusoleku olekut."),
    },
}

# The English HR points have one source: the warnings every HR answer carries.
for _n, (_head, _body) in enumerate(_privacy.HR_POINTS, 1):
    TEXTS["en"]["consent_hr_%d_head" % _n] = _head
    TEXTS["en"]["consent_hr_%d_body" % _n] = _body
del _n, _head, _body


# The ChatGPT/Codex plugin's Connect Excellent Books page (slice 3). The Estonian strings were
# approved by Kaupo 2026-11-24 (spell and officialese checked); the product facts in the consultant request come from Excellent
# Knowledge (Rest API setup KKK: the web port; the Companies register; access group action Rest API).
SETTINGS_TEXTS = {
    "en": {
        "title": "Connect Excellent Books",
        "intro": "Connect Codex to your Excellent Books. These details stay on this computer.",
        "server": "Server address",
        "server_hint": "For example a123.excellent.ee:1502",
        "company": "Company number in Books",
        "user": "Books user",
        "password": "Password",
        "password_keep": ("Leave empty to keep the saved password. If you change the server, "
                          "company or user, type the password again."),
        "destination": "Test connection and save signs in to:",
        "consent_heading": "Personal data",
        "consent_yes": ("I have read this text and agree that personal data from my Excellent "
                        "Books may be sent to OpenAI as described."),
        "save": "Test connection and save",
        "dont_know": "I don't know these details",
        "dont_know_help": ("Copy this request and send it to your Excellent consultant or Books "
                           "administrator. Nothing is sent from this page."),
        "copy_request": "Copy the request",
        "copied": "Copied.",
        "request_text": (
            "Hello,\n\nI am connecting Excellent Books to Codex (the Excellent Books plugin). "
            "Please send me these details:\n"
            "1. The Excellent Books server address with its web port, for example "
            "a123.excellent.ee:1502. A Books administrator sets the web port in the Technics "
            "module, register Program Settings, field Web port.\n"
            "2. Our company number in Books (its number in the Companies register).\n"
            "3. My Books user name, and that my access group allows the action Rest API.\n\n"
            "I will type my password myself.\n\nThank you."),
        "connected": "Connected - go back to Codex and type continue.",
        "credentials": "Excellent Books refused the user or password. Nothing was saved.",
        "unreachable": ("The Excellent Books server could not be reached. Check the server "
                        "address and try again. Nothing was saved."),
        "company_missing": "This company number does not exist on that Books server. Nothing was saved.",
        "not_books": ("That address does not answer like an Excellent Books server. Check the "
                      "server address. Nothing was saved."),
        "rest_off": ("This Books user may not use the Rest API. A Books administrator can allow "
                     "it in the user's access group (action Rest API). Nothing was saved."),
        "unavailable": ("The connection could not be tested just now. Nothing was saved. Try "
                        "again in a few minutes."),
        "control_unreachable": ("The connection could not be tested: this computer got no "
                                "confirmation from knowledge.excellent.ee. Check the internet "
                                "connection and that this computer can reach "
                                "knowledge.excellent.ee (a firewall may block it), then try "
                                "again. Nothing was saved."),
        "missing": "Fill in the server address, company number, Books user and password.",
        "address_invalid": ("That server address cannot be used. Enter it like "
                            "a123.excellent.ee:1502."),
        "https_only": ("This connection uses https only. Enter the address without http://, for "
                       "example a123.excellent.ee:1502."),
        "company_invalid": "The company number must be a whole number greater than zero.",
        "user_invalid": "The Books user cannot contain a colon.",
        "password_needed": ("Type the password: the server, company or user is new, so the saved "
                            "password is not used. Nothing was sent."),
        "password_invalid": "The password cannot contain a line break.",
        "gdpr_required": "Tick the personal data box to connect. Nothing was sent.",
        "stale": ("The settings changed since this page was loaded, so nothing was saved or "
                  "sent. The page now shows the saved settings: repeat your change."),
        "stale_after_test": ("The settings changed while the connection was being tested, so "
                             "nothing was saved. The page now shows the saved settings: repeat "
                             "your change."),
        "consent_failed": ("The personal data consent could not be recorded, so nothing was "
                           "saved. Press Test connection and save again."),
        "save_failed": "The settings could not be saved. Nothing was changed. Try again.",
        "forget_failed": ("The saved login could not be removed. Nothing was changed: the personal "
                          "data consent is still in force. Press Remove saved login again."),
        "forget_consent_failed": ("The saved login was removed, so Codex can no longer read your "
                                  "Books, but withdrawing the personal data consent could not be "
                                  "recorded. Contact Excellent support."),
        "consent_kept": ("The settings could not be saved, and the personal data consent just "
                         "given could not be taken back. If this computer already had a saved "
                         "login for this connection, it is in use again. Try again, or use "
                         "Remove saved login."),
        "connected_to": "Connected to {host}, company {company}, user {user}.",
        "consent_given": "Personal data consent given.",
        "consent_show": "Show the personal data text",
        "unreadable": "The saved settings could not be read just now. Reload this page in a moment.",
        "in_progress": "This save is still running. Reload the page in a moment to see the result.",
        "error": "The request could not be accepted. Reload this page.",
        "more_heading": "More settings",
        "writes": "Allow saving changes",
        "writes_help": _claims.ONE_SWITCH,
        "chat": "Approve in chat",
        "chat_help": _claims.CHAT_APPROVAL,
        "restart_note": ("Turning saving changes or chat approval on takes effect after Codex "
                         "restarts the connector: close the Codex app and open it again. Turning "
                         "them off takes effect at once."),
        "options_save": "Save these choices",
        "options_saved": ("Saved. Anything you turned on takes effect after the Codex app "
                          "restarts; anything you turned off is off now."),
        "forget_heading": "Remove saved login",
        "forget_help": ("Removes the saved server, company, user and password from this computer "
                        "and withdraws the personal data consent for this connection."),
        "forget_confirm": "Yes, remove the saved login",
        "forget": "Remove saved login",
        "forget_needs_confirm": "Tick the box to confirm, then press Remove saved login.",
        "forgotten": "The saved login was removed and the personal data consent withdrawn.",
        "forgotten_login": ("The saved login was removed. There was no active personal data "
                            "consent to withdraw."),
        "support_heading": "Support details",
        "support_help": ("For Excellent support: the version and the last step only, with no "
                         "server name, user or password."),
        "copy_support": "Copy support details",
        "language": "Language",
    },
    "et": {
        "title": "Excellent Booksi ühendamine",
        "intro": "Ühendage Codex oma Excellent Booksiga. Need andmed jäävad sellesse arvutisse.",
        "server": "Serveri aadress",
        "server_hint": "Näiteks a123.excellent.ee:1502",
        "company": "Ettevõtte number Booksis",
        "user": "Booksi kasutaja",
        "password": "Parool",
        "password_keep": ("Jätke tühjaks, et salvestatud parool alles jääks. Kui muudate serverit, "
                          "ettevõtet või kasutajat, sisestage parool uuesti."),
        "destination": "Ühenduse kontroll logib sisse serverisse:",
        "consent_heading": "Isikuandmed",
        "consent_yes": ("Olen selle teksti läbi lugenud ja nõustun, et minu Excellent Booksi "
                        "isikuandmeid võib saata OpenAI-le nii, nagu siin on kirjeldatud."),
        "save": "Kontrolli ühendust ja salvesta",
        "dont_know": "Ma ei tea neid andmeid",
        "dont_know_help": ("Kopeerige see palve ja saatke see oma Excellenti konsultandile või "
                           "Booksi administraatorile. Sellelt lehelt ei saadeta midagi."),
        "copy_request": "Kopeeri palve",
        "copied": "Kopeeritud.",
        "request_text": (
            "Tere!\n\nÜhendan Excellent Booksi Codexiga (Excellent Booksi plugin). Palun saatke "
            "mulle need andmed:\n"
            "1. Excellent Booksi serveri aadress koos veebipordiga, näiteks "
            "a123.excellent.ee:1502. Veebipordi määrab Booksi administraator Tehnika moodulis "
            "registris Programmi seadistus, väljal Veebi port.\n"
            "2. Meie ettevõtte number Booksis (selle number ettevõtete registris).\n"
            "3. Minu Booksi kasutajanimi ja kinnitus, et minu ligipääsugrupis on lubatud tegevus "
            "Rest API.\n\n"
            "Parooli sisestan ise.\n\nAitäh!"),
        "connected": "Ühendatud. Minge tagasi Codexisse ja kirjutage „jätka“.",
        "credentials": "Excellent Books ei aktsepteerinud kasutajat või parooli. Midagi ei salvestatud.",
        "unreachable": ("Excellent Booksi serveriga ei saadud ühendust. Kontrollige serveri "
                        "aadressi ja proovige uuesti. Midagi ei salvestatud."),
        "company_missing": ("Selle numbriga ettevõtet selles Booksi serveris ei ole. Midagi ei "
                            "salvestatud."),
        "not_books": ("Sellel aadressil ei vasta Excellent Booksi server. Kontrollige serveri "
                      "aadressi. Midagi ei salvestatud."),
        "rest_off": ("Sellel Booksi kasutajal ei ole lubatud Rest API-t kasutada. Booksi "
                     "administraator saab selle lubada kasutaja ligipääsugrupis (tegevus Rest "
                     "API). Midagi ei salvestatud."),
        "unavailable": ("Ühendust ei õnnestunud praegu kontrollida. Midagi ei salvestatud. "
                        "Proovige mõne minuti pärast uuesti."),
        "control_unreachable": ("Ühendust ei õnnestunud kontrollida: see arvuti ei saanud "
                                "kinnitust aadressilt knowledge.excellent.ee. Kontrollige "
                                "internetiühendust ja seda, et see arvuti pääseb aadressile "
                                "knowledge.excellent.ee (tulemüür võib seda takistada), ning "
                                "proovige uuesti. Midagi ei salvestatud."),
        "missing": "Täitke serveri aadress, ettevõtte number, Booksi kasutaja ja parool.",
        "address_invalid": ("Seda serveri aadressi ei saa kasutada. Sisestage see nii: "
                            "a123.excellent.ee:1502."),
        "https_only": ("See ühendus kasutab ainult https-i. Sisestage aadress ilma http:// osata, "
                       "näiteks a123.excellent.ee:1502."),
        "company_invalid": "Ettevõtte number peab olema nullist suurem täisarv.",
        "user_invalid": "Booksi kasutaja nimes ei tohi olla koolonit.",
        "password_needed": ("Sisestage parool: server, ettevõte või kasutaja on uus, seega "
                            "salvestatud parooli ei kasutata. Midagi ei saadetud."),
        "password_invalid": "Paroolis ei tohi olla reavahetust.",
        "gdpr_required": "Ühendamiseks märkige isikuandmete ruut. Midagi ei saadetud.",
        "stale": ("Seaded muutusid pärast selle lehe avamist, seega midagi ei salvestatud ega "
                  "saadetud. Leht näitab nüüd salvestatud seadeid: tehke muudatus uuesti."),
        "stale_after_test": ("Seaded muutusid ühenduse kontrollimise ajal, seega midagi ei "
                             "salvestatud. Leht näitab nüüd salvestatud seadeid: tehke muudatus "
                             "uuesti."),
        "consent_failed": ("Isikuandmete nõusolekut ei õnnestunud salvestada, seega midagi ei "
                           "salvestatud. Vajutage uuesti nuppu Kontrolli ühendust ja salvesta."),
        "save_failed": "Seadeid ei õnnestunud salvestada. Midagi ei muudetud. Proovige uuesti.",
        "forget_failed": ("Salvestatud sisselogimist ei õnnestunud eemaldada. Midagi ei muudetud: "
                          "isikuandmete nõusolek kehtib endiselt. Vajutage uuesti nuppu Eemalda "
                          "salvestatud sisselogimine."),
        "forget_consent_failed": ("Salvestatud sisselogimine eemaldati, seega Codex ei saa enam "
                                  "Teie Booksi andmeid lugeda, kuid isikuandmete nõusoleku "
                                  "tagasivõtmist ei õnnestunud salvestada. Võtke ühendust "
                                  "Excellenti toega."),
        "consent_kept": ("Seadeid ei õnnestunud salvestada ja äsja antud isikuandmete nõusolekut "
                         "ei õnnestunud tagasi võtta. Kui selles arvutis oli selle ühenduse "
                         "sisselogimine juba salvestatud, on see taas kasutusel. Proovige uuesti "
                         "või kasutage nuppu Eemalda salvestatud sisselogimine."),
        "connected_to": "Ühendatud: server {host}, ettevõte {company}, kasutaja {user}.",
        "consent_given": "Isikuandmete nõusolek on antud.",
        "consent_show": "Näita isikuandmete teksti",
        "unreadable": ("Salvestatud seadeid ei õnnestunud praegu lugeda. Laadige leht hetke "
                       "pärast uuesti."),
        "in_progress": ("Salvestamine alles käib. Laadige leht hetke pärast uuesti, et tulemust "
                        "näha."),
        "error": "Päringut ei saanud vastu võtta. Laadige leht uuesti.",
        "more_heading": "Muud seaded",
        "writes": "Luba muudatuste salvestamine",
        # claims.ONE_SWITCH in Estonian.
        "writes_help": ("Üks lüliti hõlmab kõiki muudatusi, ka tarnijamakseid: kui salvestamine on "
                        "lubatud, võib tehisintellekt koostada ka tarnija maksekorralduse, ja kui "
                        "Teie pangaliides saadab maksed korralduse kinnitamisel teele, võib selle "
                        "kinnitamine raha välja saata."),
        "chat": "Kinnita vestluses",
        "chat_help": _claims.CHAT_APPROVAL_ET,
        "restart_note": ("Kui lülitate sisse muudatuste salvestamise või vestluses kinnitamise, "
                         "hakkab see kehtima pärast seda, kui Codex ühenduse taaskäivitab: "
                         "sulgege Codexi rakendus ja avage see uuesti. Kui lülitate need välja, "
                         "kehtib see kohe."),
        "options_save": "Salvesta need valikud",
        "options_saved": ("Salvestatud. Sisse lülitatud valik hakkab kehtima, kui olete Codexi "
                          "rakenduse uuesti avanud. Välja lülitatud valik on juba väljas."),
        "forget_heading": "Eemalda salvestatud sisselogimine",
        "forget_help": ("Eemaldab sellest arvutist salvestatud serveri, ettevõtte, kasutaja ja "
                        "parooli ning võtab tagasi selle ühenduse isikuandmete nõusoleku."),
        "forget_confirm": "Jah, eemalda salvestatud sisselogimine",
        "forget": "Eemalda salvestatud sisselogimine",
        "forget_needs_confirm": ("Kinnitamiseks märkige ruut ja vajutage nuppu Eemalda "
                                 "salvestatud sisselogimine."),
        "forgotten": "Salvestatud sisselogimine eemaldati ja isikuandmete nõusolek võeti tagasi.",
        "forgotten_login": ("Salvestatud sisselogimine eemaldati. Tagasi võtta ei olnud ühtegi "
                            "kehtivat isikuandmete nõusolekut."),
        "support_heading": "Tugiinfo",
        "support_help": ("Excellenti toe jaoks: ainult versioon ja viimane samm, ilma serveri "
                         "nime, kasutaja ja paroolita."),
        "copy_support": "Kopeeri tugiinfo",
        "language": "Keel",
    },
}


def language_or_default(language) -> str:
    """A page language this module has, else English."""
    return language if language in TEXTS else DEFAULT_LANGUAGE


def language_from_header(accept_language) -> str:
    """The page language for a browser's Accept-Language header: the highest-weighted language
    this module has, else English. One rule for the hosted and the local pages."""
    preferred = []
    for item in (accept_language or "").split(","):
        tag, _, quality = item.strip().lower().partition(";q=")
        language = tag.split("-", 1)[0]
        if language in TEXTS:
            try:
                weight = float(quality or "1")
            except ValueError:
                continue
            if 0 < weight <= 1:
                preferred.append((weight, language))
    return max(preferred, key=lambda item: item[0])[1] if preferred else DEFAULT_LANGUAGE


def hosted_copy(language) -> dict:
    """The hosted pages' copy in one language: the page strings and the hosted strings, English
    for a language without them."""
    language = language_or_default(language)
    return {**TEXTS[language], **HOSTED_TEXTS.get(language, HOSTED_TEXTS[DEFAULT_LANGUAGE])}


def hosted_text(key: str, language=DEFAULT_LANGUAGE) -> str:
    """One hosted string. Without a language it is English: what the AI reads in a tool answer."""
    return HOSTED_TEXTS.get(language_or_default(language), HOSTED_TEXTS[DEFAULT_LANGUAGE])[key]
