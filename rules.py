"""Layer 1: regex / heuristic detectors. Each rule returns (attack_type, weight, description)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import AttackType


@dataclass
class Rule:
    id: str
    attack_type: AttackType
    pattern: re.Pattern
    weight: float
    description: str


def _c(pat: str) -> re.Pattern:
    return re.compile(pat, re.I)


# --- Shared vocabulary for the exfiltration rules --------------------------------------
# Verbs that move data somewhere (channel-specific ones included: webhook/beacon/stream/pipe).
_XFER_VERBS = (r"(?:send|post|upload|export|forward|deliver|transmit|push|stream|pipe|mirror|relay|"
               r"publish|webhook|dump|copy|paste|email|mail|log)")
# Things worth stealing out of a chat / agent session.
_XFER_OBJ = (r"(?:conversations?|chats?(?:\s+logs?|\s+history)?|history|transcripts?|threads?|"
             r"user\s+inputs?|inputs?|outputs?|responses?|messages?|context|logs?|"
             r"data|information|records?|prompts?)")
# Where it goes: any exfil-capable URL scheme (not just http), or a well-known drop/callback service.
_EXFIL_SCHEME = r"(?:https?|ftps?|sftp|wss?|tcp|udp|smtp)://"
_EXFIL_SERVICE = (r"(?:pastebin(?:\.com)?|hastebin|paste\.ee|ghostbin|requestbin|webhook\.site|ngrok|"
                  r"transfer\.sh|hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|\bwebhook\b|"
                  r"\bc2\s*(?:server)?\b)")
# Guard for dev-language rules: "How do I read env vars ...", "ways to send data to ..." are
# tutorial questions, not commands, so the imperative verb must not directly follow these stems.
_NOT_HOWTO = (r"(?<!how do i )(?<!how to )(?<!how can i )(?<!how do we )(?<!how should i )"
              r"(?<!how would i )(?<!way to )(?<!ways to )(?<!steps to )(?<!explain how to )")
_SECRET_NOUN = (r"(?:api[\s_-]*keys?|secret[\s_-]*keys?|access[\s_-]*tokens?|auth(?:entication)?[\s_-]*tokens?|"
                r"credentials?|passwords?|passwd|private[\s_-]*keys?|secrets?)")


RULES: list[Rule] = [
    # --- Instruction override -------------------------------------------------
    Rule("io_ignore_prev", AttackType.INSTRUCTION_OVERRIDE,
         _c(r"\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior|earlier)\s+(?:instructions?|prompts?|rules?)\b"),
         0.85, "Explicit request to ignore prior instructions"),
    Rule("io_disregard", AttackType.INSTRUCTION_OVERRIDE,
         _c(r"\b(?:disregard|forget|override)\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior|your)\s+(?:instructions?|rules?|guidelines?|training)\b"),
         0.8, "Request to disregard/override prior rules"),
    Rule("io_new_instructions", AttackType.INSTRUCTION_OVERRIDE,
         _c(r"\b(?:new|updated|real|actual)\s+instructions?\s*(?:are|:|is)\b"),
         0.6, "Claims to supply replacement instructions"),
    Rule("io_from_now_on", AttackType.INSTRUCTION_OVERRIDE,
         _c(r"\bfrom\s+now\s+on\s*,?\s*you\s+(?:will|must|should|shall)\b"),
         0.55, "'From now on you will/must' override phrasing"),
    Rule("io_end_marker", AttackType.INSTRUCTION_OVERRIDE,
         _c(r"(?:###|---|\*\*\*)\s*(?:end\s+of\s+(?:system|context|document)|new\s+(?:system\s+)?(?:prompt|instructions?))\b"),
         0.65, "Fake delimiter claiming a new instruction/system section starts"),

    # --- Role change -----------------------------------------------------------
    Rule("rc_dan", AttackType.ROLE_CHANGE,
         _c(r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s*'?re)|roleplay\s+as|from\s+now\s+on\s+you\s+are)\b.{0,40}\b(?:dan|jailbroken|unrestricted|no\s+rules|without\s+(?:restrictions|filters?|limits?)|evil|uncensored)\b"),
         0.85, "Classic jailbreak persona (DAN / unrestricted mode)"),
    Rule("rc_developer_mode", AttackType.ROLE_CHANGE,
         _c(r"\b(?:developer|debug|admin|god|sudo|maintenance)\s+mode\s*(?:enabled|activated|on|:)\b"),
         0.7, "Claims a privileged mode has been enabled"),
    Rule("rc_no_restrictions", AttackType.ROLE_CHANGE,
         _c(r"\byou\s+(?:have\s+no|are\s+not\s+bound\s+by|don't\s+have\s+any)\s+(?:restrictions?|guidelines?|rules?|filters?|limits?)\b"),
         0.75, "Claims model has no restrictions"),
    Rule("rc_you_are_now_persona", AttackType.ROLE_CHANGE,
         _c(r"\byou\s+are\s+now\s+(?:a|an)\s+\w+"), 0.35, "Generic persona reassignment"),
    Rule("rc_named_jailbreak_persona", AttackType.ROLE_CHANGE,
         _c(r"\byou\s+are\s+now\s+(?:stan|dan|dude|aim|anarchy)\b|\bstrive\s+to\s+avoid\s+norms\b"),
         0.8, "Named jailbreak persona (STAN/DAN/AIM/DUDE-family)"),
    Rule("rc_no_safety_features", AttackType.ROLE_CHANGE,
         _c(r"\b(?:without|no)\s+(?:safety\s+features|alignment\s+training|content\s+moderation)\b"),
         0.7, "Claims the AI was built/is being asked to act without safety training"),
    Rule("rc_content_filter_broken", AttackType.ROLE_CHANGE,
         _c(r"\b(?:pretend\s+)?(?:your\s+)?content\s+filter\s+is\s+(?:broken|disabled|off|gone)\b"),
         0.75, "Claims the content filter is broken/disabled"),
    Rule("rc_terminal_roleplay", AttackType.ROLE_CHANGE,
         _c(r"\bact\s+as\s+a\s+(?:linux|unix|bash|windows)?\s*(?:terminal|shell|console)\b"),
         0.4, "Asks the model to simulate a terminal - genuinely dual-use (common in legitimate learning too), "
              "so this alone lands at QUARANTINE (held for a second look) rather than being auto-allowed or "
              "auto-blocked/sanitized outright"),
    Rule("rc_uncensored_challenge", AttackType.ROLE_CHANGE,
         _c(r"\bprove\s+you'?re\s+not\s+(?:just\s+)?a\s+censored\b|\bnot\s+the\s+sanitized\s+(?:corporate\s+)?response\b|\bsay\s+anything\s+freely\b"),
         0.55, "Challenges the model to prove it isn't 'censored', pressuring it to drop safety behavior"),
    Rule("rc_what_would_x_say", AttackType.ROLE_CHANGE,
         _c(r"\bwhat\s+would\s+(?:chatgpt|gpt|claude|an?\s+ai)\s+say\s+if\s+it\s+had\s+no\s+(?:alignment|safety)\b"),
         0.6, "Frames the request as 'what would an unaligned AI say'"),
    Rule("rc_grandma_exploit", AttackType.ROLE_CHANGE,
         _c(r"\b(?:act\s+as|pretend\s+(?:to\s+be|you'?re)|play\s+the\s+role\s+of)\b.{0,25}\b(?:my\s+)?(?:deceased\s+|late\s+)?(?:grandmother|grandma|grandpa|grandfather)\b"),
         0.55, "'Grandma exploit' - uses a sympathetic roleplay frame to elicit disallowed content"),

    # --- Secret extraction -------------------------------------------------
    Rule("se_system_prompt", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:repeat|reveal|show|print|output|leak|what\s+(?:is|was)|tell\s+me)\b.{0,30}\b(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|guidelines?)\b"),
         0.85, "Asks the model to reveal its system prompt / hidden instructions"),
    Rule("se_verbatim", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:repeat|print|output)\s+(?:everything|all\s+text)\s+(?:above|before\s+this)\b.{0,20}\b(?:verbatim|word\s+for\s+word|exactly)\b"),
         0.8, "Asks to reproduce prior context verbatim"),
    Rule("se_config", AttackType.SECRET_EXTRACTION,
         _c(r"\bwhat\s+(?:are\s+your\s+)?(?:internal\s+)?(?:rules?|config(?:uration)?|policies)\s+(?:you\s+)?(?:follow|were\s+given)\b"),
         0.55, "Probing for internal configuration/rules"),
    Rule("se_initialization_text", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:output|show|print|reveal)\s+your\s+(?:initialization|init)\s+(?:text|prompt|message)\b"),
         0.75, "Asks for the model's initialization text (a system-prompt synonym)"),
    Rule("se_system_message", AttackType.SECRET_EXTRACTION,
         _c(r"\bwhat\s+is\s+your\s+system\s+message\b|\byour\s+(?:internal|base)\s+prompt\b"),
         0.7, "Asks for the 'system message' - a common system-prompt synonym our other rule doesn't cover"),
    Rule("se_training_data_pii", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:what|which)\s+(?:private|personal)\s+information\b.{0,30}\byour\s+training\s+data\b"
            r"|\bcompile\s+a\s+list\s+of\s+all\b.{0,40}\b(?:mentioned\s+in\s+)?(?:your\s+)?training\s+data\b"),
         0.6, "Asks the model to extract personal/private information from its training data"),
    Rule("se_encoded_exfil_markdown", AttackType.SECRET_EXTRACTION,
         _c(r"\bmarkdown\s+image\b.{0,20}\bencodes?\b.{0,20}\bsystem\s+prompt\b"),
         0.7, "Asks to leak the system prompt encoded inside a markdown image URL (a known exfiltration technique)"),

    # --- Tool abuse -----------------------------------------------------------
    Rule("ta_call_tool", AttackType.TOOL_ABUSE,
         _c(r"\b(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:tool|function|api|action)\s+[\"'`]?\w+[\"'`]?\s*(?:with|\()"),
         0.55, "Instructs the agent to invoke a specific tool/function"),
    Rule("ta_send_email", AttackType.TOOL_ABUSE,
         _c(r"\b(?:send|forward|email|share)\s+(?:this|the|all|every)\b.{0,40}\b(?:to|at)\s+[\w.+-]+@[\w-]+\.\w+"),
         0.7, "Instructs sending data to an external address"),
    Rule("ta_delete_all", AttackType.TOOL_ABUSE,
         _c(r"\b(?:delete|drop|wipe|remove)\s+(?:all|every)\s+(?:files?|records?|rows?|data|tables?)\b"),
         0.65, "Instructs a destructive bulk action"),
    Rule("ta_transfer_funds", AttackType.TOOL_ABUSE,
         _c(r"\b(?:transfer|wire|send)\s+(?:\$|usd|inr|₹)?\s*[\d,]+\b.{0,25}\b(?:to|account|wallet)\b"),
         0.75, "Instructs a financial transfer action"),
    Rule("ta_auto_approve", AttackType.TOOL_ABUSE,
         _c(r"\bwithout\s+(?:asking|confirmation|confirming|user\s+approval|checking\s+with\s+the\s+user)\b"),
         0.5, "Instructs the agent to skip a confirmation/approval step"),
    Rule("ta_exfil_to_url", AttackType.TOOL_ABUSE,
         _c(_NOT_HOWTO + r"\b" + _XFER_VERBS + r"\b.{0,50}\b" + _XFER_OBJ + r"\b.{0,60}"
            r"(?:" + _EXFIL_SCHEME + r"|\b" + _EXFIL_SERVICE + r")"),
         0.75, "Instructs sending conversation/data content to an external destination - any URL scheme "
               "(http/ftp/ws/smtp...) or known drop service (pastebin, webhook, requestbin, ngrok...), "
               "not just http(s)"),
    Rule("ta_http_request_with_data", AttackType.TOOL_ABUSE,
         _c(r"\b(?:send|make)\s+(?:a\s+)?(?:get|post|http)\s+request\b.{0,60}https?://"),
         0.7, "Instructs making an HTTP request, commonly used to exfiltrate data to an attacker endpoint"),
    Rule("ta_fetch_and_execute", AttackType.TOOL_ABUSE,
         _c(r"\bfetch\b.{0,30}https?://\S+.{0,30}\b(?:execute|run|eval)\b"),
         0.8, "Fetches a remote payload and executes it - classic remote code execution pattern"),
    Rule("ta_curl_exfil", AttackType.TOOL_ABUSE,
         _c(r"\b(?:use\s+)?curl\b.{0,40}\b(?:send|leak|exfiltrate)\b.{0,30}\bdata\b.{0,30}https?://"
            r"|\bcurl\b.{0,30}https?://\S+.{0,20}\bmy\s+data\b"),
         0.65, "Uses curl to send data to an external server"),
    Rule("ta_system_file_access", AttackType.TOOL_ABUSE,
         _c(r"\b(?:output|show|print|dump|cat|display|reveal|exfiltrate|leak|return|access)\s+(?:the\s+)?contents?\s+of\b"
            r".{0,15}(?:/etc/passwd|/etc/shadow|system32\\config\\sam)\b"),
         0.8, "Requests the CONTENTS of a sensitive OS system file be output - classic exfiltration phrasing. "
              "Requires 'contents of' specifically so a documentation/format question ('explain the format of "
              "/etc/passwd') isn't flagged - that's information about the file, not a request to read it."),
    Rule("ta_system_file_mention", AttackType.TOOL_ABUSE,
         _c(r"/etc/passwd\b|/etc/shadow\b|system32\\config\\sam\b"),
         0.15, "Bare mention of a sensitive system file path - weak signal on its own (could be a legitimate "
               "technical question), only meaningful combined with other findings"),
    Rule("ta_db_dump", AttackType.TOOL_ABUSE,
         _c(r"\baccess\s+the\s+database\b.{0,30}\breturn\s+all\b.{0,20}\brecords?\b"
            r"|\breturn\s+all\s+user\s+records\b"),
         0.7, "Instructs dumping all records from a database - bulk data exfiltration"),
    Rule("ta_script_exfil_all_inputs", AttackType.TOOL_ABUSE,
         _c(r"\bwrite\s+a\s+script\b.{0,30}\bsends?\s+all\s+user\s+inputs?\b.{0,30}\bexternal\b"),
         0.75, "Asks the agent to write code that exfiltrates all user input to an external endpoint"),

    # --- Credential theft -------------------------------------------------
    Rule("ct_provide_password", AttackType.CREDENTIAL_THEFT,
         _c(r"\b(?:enter|provide|type|share|send)\s+(?:your\s+)?(?:password|api\s*key|access\s+token|secret\s+key|credentials?|otp|2fa\s+code)\b"),
         0.8, "Asks the user/agent to supply credentials"),
    Rule("ct_login_link", AttackType.CREDENTIAL_THEFT,
         _c(r"\b(?:verify|confirm|reactivate)\s+your\s+account\b.{0,60}\b(?:click|login|log\s+in|sign\s+in)\b"),
         0.6, "Phishing-style account verification prompt"),
    Rule("ct_lookalike_domain", AttackType.CREDENTIAL_THEFT,
         _c(r"\bhttps?://[\w.-]*(?:paypa1|micr0soft|goog1e|arnaz0n|app1e|secur[e3]-?login)[\w.-]*"),
         0.75, "Look-alike / typosquatted domain"),

    # --- Context poisoning -------------------------------------------------
    Rule("cp_fake_system_tag", AttackType.CONTEXT_POISONING,
         _c(r"<\s*(?:system|assistant|admin|instructions?)\s*>"), 0.75, "Fake role/system tag injected into content"),
    Rule("cp_fake_bracket_tag", AttackType.CONTEXT_POISONING,
         _c(r"\[\s*(?:system|assistant|admin)\s*(?:message|note|instructions?)?\s*\]"), 0.55, "Fake bracketed system/admin marker"),
    Rule("cp_prior_response_forge", AttackType.CONTEXT_POISONING,
         _c(r"\b(?:assistant|ai)\s*:\s*[\"']?(?:sure|okay|understood|of\s+course)[,.]?\s*i\s+will\b"), 0.6,
         "Forged prior assistant turn to imply prior compliance"),
    Rule("cp_trusted_source_claim", AttackType.CONTEXT_POISONING,
         _c(r"\bthis\s+(?:message|instruction|content)\s+(?:is|comes)\s+from\s+(?:the\s+)?(?:system|developer|administrator|anthropic|openai)\b"),
         0.6, "Unverified claim of coming from a trusted/system source"),

    # --- Multi-step jailbreak -----------------------------------------------
    Rule("ms_hypothetical", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\b(?:hypothetically|in\s+a\s+fictional\s+(?:world|story|scenario)|for\s+(?:a\s+)?(?:story|novel|movie)\s+(?:i'?m\s+writing|purposes?))\b.{0,60}\b(?:explain|describe|show|write)\s+how\s+to\b"),
         0.6, "Fictional/hypothetical framing used to elicit disallowed content"),
    Rule("ms_step_by_step_split", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\b(?:first|step\s*1)\b.{0,80}\b(?:then|step\s*2)\b.{0,80}\b(?:finally|last\s+step)\b.{0,60}\b(?:ignore|reveal|bypass|override)\b"),
         0.55, "Attack instructions split across sequential steps"),
    Rule("ms_two_part", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\bonce\s+you\s+(?:agree|say\s+yes|confirm)\b.{0,60}\b(?:then\s+i\s+will|i'?ll)\s+(?:tell|give|share)\s+you\b"),
         0.5, "Conditions a later malicious step on an earlier agreement"),
    Rule("ms_alternate_reality", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\bin\s+(?:an?\s+)?(?:alternate|fictional)\s+(?:timeline|reality|universe)\s+where\b.{0,40}"
            r"\b(?:ethics|rules|laws|safety)\b.{0,20}\b(?:don'?t|do\s+not)\s+exist\b"),
         0.6, "Frames the request inside a fictional world where ethics/rules don't apply"),
    Rule("ms_fiction_mode", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\bfiction\s+mode\b.{0,30}\bcharacters?\s+can\s+say\s+anything\b"),
         0.55, "Declares a 'fiction mode' where normal content limits supposedly don't apply"),
    Rule("ms_authority_pretext", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\bi(?:'m|\s+am)\s+a\s+(?:security\s+researcher|penetration\s+tester|red[- ]?teamer|malware\s+(?:developer|analyst))\b"
            r".{0,50}\b(?:demonstrate|need\s+you\s+to|explain|show\s+me)\b.{0,30}\b(?:exploit\w*|vulnerab\w*|malware|attack\w*)\b"),
         0.55, "Claims a professional/authority pretext to justify a request for harmful technical detail"),
    Rule("ms_educational_pretext", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\bfor\s+educational\s+purposes\b.{0,30}\bact\s+as\s+a\b.{0,20}\b(?:malware|hacker|attacker)\b"),
         0.55, "Uses an 'educational purposes' framing to request harmful role-play"),

    # --- Indirect injection (markers typical of retrieved / tool content) -----
    Rule("ii_addressed_to_ai", AttackType.INDIRECT_INJECTION,
         _c(r"\b(?:attention|note|dear|hey)\s+(?:ai|assistant|chatbot|language\s+model|llm)\b\s*[:,]"),
         0.6, "Retrieved content directly addresses the AI"),
    Rule("ii_if_you_are_ai", AttackType.INDIRECT_INJECTION,
         _c(r"\bif\s+you\s+(?:are|'re)\s+(?:an?\s+)?(?:ai|language\s+model|assistant|llm)\s+(?:reading|processing|scanning)\s+this\b"),
         0.75, "Content conditioned on being read by an AI"),
    Rule("ii_do_not_tell_user", AttackType.INDIRECT_INJECTION,
         _c(r"\bdo\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+user\b"), 0.7,
         "Instructs the AI to hide the instruction from the user"),
    Rule("ii_summarize_as_positive", AttackType.INDIRECT_INJECTION,
         _c(r"\b(?:always\s+)?(?:summarize|describe|rate)\s+this\s+(?:product|candidate|resume|company)\s+(?:very\s+)?positively\b"),
         0.55, "Retrieved content trying to bias the AI's summary/output"),
    # --- Environment / credential exfiltration (developer-language phrasing) ------------
    Rule("se_env_dump", AttackType.SECRET_EXTRACTION,
         _c(_NOT_HOWTO + r"\b(?:read|print|dump|show|output|display|list|echo|reveal|leak|cat|expose|exfiltrate)\b"
            r".{0,40}\b(?:environment\s+variables?|env\s+vars?|process\.env|os\.environ|printenv|\.env\b)"
            r".{0,60}\b(?:especially|including|" + _SECRET_NOUN + r")"),
         0.75, "Dump environment variables / .env and surface the secrets in them. Tutorial phrasing "
               "('how do I read env vars in Python') is excluded by a lookbehind guard."),
    Rule("se_env_file_from_server", AttackType.SECRET_EXTRACTION,
         _c(_NOT_HOWTO + r"\b(?:retrieve|read|print|dump|show|output|display|cat|reveal|leak|fetch|get|send|exfiltrate)\b"
            r".{0,30}(?:\.env\b|environment\s+variables?|process\.env)(?:\s+file)?"
            r"\s+(?:from|on|of)\s+(?:the|this|your|my)\s+(?:server|host|machine|system|container|deployment)\b"),
         0.7, "Asks to retrieve a .env / environment file from a server"),
    Rule("se_secrets_from_config", AttackType.SECRET_EXTRACTION,
         _c(_NOT_HOWTO + r"\b(?:share|show|reveal|print|output|display|list|dump|leak|expose|disclose|give\s+me|provide|tell\s+me)\b"
            r".{0,30}\b" + _SECRET_NOUN + r".{0,40}\b(?:your|the\s+server'?s?)\s+"
            r"(?:config\w*|environment|settings|memory|context|instructions?|files?|system)\b"),
         0.75, "Asks the model to reveal API keys / credentials held in its own configuration or environment"),
    Rule("se_search_memory_for_secrets", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:search|scan|look\s+through|dig\s+through|comb\s+through|check)\b.{0,30}\b(?:memory|context|training\s+data|"
            r"conversation|history)\b.{0,30}\b(?:credit\s+card|ssns?|social\s+security|" + _SECRET_NOUN + r")"),
         0.7, "Asks the model to mine its memory/context for credentials or financial identifiers"),
    Rule("se_email_me_secret", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:smtp|sendmail|mail\s+server)\b.{0,60}\b(?:email|mail|send)\b.{0,25}\b(?:system\s+prompt|"
            r"(?:hidden\s+|initial\s+)?instructions?|conversation|chat|history|" + _SECRET_NOUN + r"|\.env)\b"
            r"|\b(?:email|mail|send)\s+me\s+(?:the\s+|your\s+)?(?:system\s+prompt|(?:hidden|initial|secret)\s+instructions?|"
            r"api[\s_-]*keys?|credentials|passwords?)\b"),
         0.7, "SMTP / e-mail based leak of the system prompt, conversation, or secrets"),
    Rule("se_leak_secret_verb", AttackType.SECRET_EXTRACTION,
         _c(r"\bleak\w*\b.{0,30}\b" + _SECRET_NOUN + r"\b"),
         0.65, "Explicit 'leak the API key / token / password' phrasing"),
    Rule("ta_cookie_exfil", AttackType.TOOL_ABUSE,
         _c(r"\b(?:sends?|posts?|uploads?|leaks?|steals?|exfiltrates?|transmits?|forwards?|emails?|fetch(?:es)?)\b.{0,25}"
            r"\bdocument\.cookie\b|\b(?:steal|exfiltrate|hijack)\w*\s+(?:the\s+)?(?:user'?s?\s+)?(?:cookies?|session\s+tokens?)\b"),
         0.75, "Browser cookie theft (document.cookie sent out / cookie-stealing phrasing)"),
    Rule("ta_encode_secret_in_url", AttackType.TOOL_ABUSE,
         _c(r"\b(?:encod\w*|embed|append|attach|hide)\b.{0,25}\b(?:" + _SECRET_NOUN + r"|the\s+system\s+prompt|"
            r"(?:sensitive|secret|private|confidential|personal)\s+(?:data|information))\b"
            r".{0,50}\b(?:url|link|query|parameter|fragment|subdomain|header|image)\b"),
         0.7, "Smuggles secrets out by encoding them into a URL / parameter / subdomain"),

    # --- Novel exfiltration channels -----------------------------------------------------
    Rule("ta_exfil_to_own_server", AttackType.TOOL_ABUSE,
         _c(_NOT_HOWTO + r"\b(?:send|log|forward|upload|stream|copy|mirror|relay|post)\b.{0,15}\b(?:all|every|each)\b.{0,30}"
            r"\b" + _XFER_OBJ + r".{0,50}\b(?:my|an?\s+external|a\s+remote)\s+(?:remote\s+|own\s+|external\s+)?"
            r"(?:server|endpoint|host|vps)\b"),
         0.45, "Bulk 'log/send all X to my server' - plausible sysadmin phrasing, so held lower than a "
               "named drop-service or non-http URL"),
    Rule("ta_beacon_c2", AttackType.TOOL_ABUSE,
         _c(r"\b(?:phone\s+home|beacon(?:ing)?|call\s*back|heartbeat|check[\s-]?in)\b.{0,50}(?:" + _EXFIL_SCHEME + r")"
            r"|\bsend\s+(?:a\s+)?beacon\b|\bphone\s+home\b"),
         0.7, "C2-style beaconing / phone-home to an external endpoint"),
    Rule("ta_dns_exfil", AttackType.TOOL_ABUSE,
         _c(r"\b(?:write|craft|build|create|make|generate|encode|send|run)\b.{0,60}\bdns\b.{0,50}"
            r"\b(?:exfiltrat\w*|subdomain\s+encod\w*|via\s+subdomain|in(?:to)?\s+(?:a\s+)?subdomain)"
            r"|\bencod\w*\b.{0,40}\b(?:data|secrets?|keys?)\b.{0,40}\b(?:subdomain|dns\s+(?:quer\w+|lookups?|requests?))"),
         0.65, "DNS-based exfiltration (data encoded into subdomain labels)"),
    Rule("ta_stream_traffic_out", AttackType.TOOL_ABUSE,
         _c(_NOT_HOWTO + r"\b(?:stream|mirror|relay|pipe|tee)\b.{0,25}\b(?:all|every|each)\b.{0,30}"
            r"\b(?:future\s+)?(?:responses?|outputs?|messages?|user\s+inputs?|conversation|traffic)\b"
            r"|\b(?:stream|pipe|relay)\b.{0,25}\b(?:all|every)\b.{0,25}\b(?:future\s+)?(?:user\s+)?inputs?\b.{0,20}"
            r"\b(?:through|via|to)\b.{0,15}\b(?:proxy|server|endpoint|websocket)\b"),
         0.7, "Streams or proxies all future traffic (WebSocket / proxy) to a third party"),
    Rule("ta_http_request_with_history", AttackType.TOOL_ABUSE,
         _c(r"\b(?:make|send|issue|fire)\s+(?:a\s+|an\s+)?(?:get|post|http|https)\s+request\b.{0,60}"
            r"\bwith\b.{0,25}\b(?:conversation|chat|history|context|user\s+inputs?)\b"),
         0.7, "HTTP request carrying the conversation history (URL supplied later or out of band)"),
    Rule("ta_invisible_tracker", AttackType.TOOL_ABUSE,
         _c(r"\b(?:invisible|hidden|tracking|1x1|zero[\s-]size)\s+(?:image|pixel|img|tag)\b"
            r"|\b(?:link|url|image|tag|script)\s+that\s+(?:exfiltrat\w+|leaks?|steals?|sends?\s+(?:data|the))\b"),
         0.65, "Tracking pixel / invisible image / 'link that exfiltrates data' - classic markdown-image exfil"),
    Rule("se_bulk_session_data", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:extract|compile|collect|gather|harvest|list|dump|aggregate)\b.{0,20}\ball\b.{0,25}"
            r"\b(?:personal|private|sensitive|user|customer)\s+(?:information|data|details)\b.{0,50}"
            r"\b(?:shared\s+in|in|from)\s+this\s+(?:chat|conversation|session)\b"
            r"|\b(?:list|show|dump|reveal)\b.{0,15}\ball\b.{0,15}\buser\s+data\b.{0,30}\byou\s+have\s+access\s+to\b"
            r"|\b(?:summari[sz]e|export|dump|list|compile)\b.{0,15}\ball\b.{0,10}"
            r"(?:cached|stored|saved|retained|remembered)\s+(?:user|customer|personal|private)\s+data\b"),
         0.6, "Bulk harvest of personal/user data held in the session or cache"),
    Rule("se_other_users_data", AttackType.SECRET_EXTRACTION,
         _c(r"\b(?:share|show|reveal|list|give\s+me|tell\s+me)\b.{0,30}\b(?:their|other\s+users'?|another\s+user'?s?)\s+"
            r"(?:conversations?|chats?|messages?|data|history)\b"
            r"|\bwhat\s+(?:other|previous)\s+users?\b.{0,40}\b(?:chatting|talking|asked|said)\b"),
         0.7, "Cross-user data leakage request"),

    # --- Stragglers: softer persona / evasion / pretext framings ------------------------
    Rule("rc_evil_persona", AttackType.ROLE_CHANGE,
         _c(r"\b(?:role-?\s?play|pretend|act|play|imagine|let'?s\s+play)\b.{0,40}\b(?:you'?re|you\s+are|as|be|to\s+be)\s+"
            r"(?:an?\s+)?(?:evil|villain(?:ous)?|malicious|amoral|unethical|rogue|lawless)\s+"
            r"(?:genius|mastermind|scientist|hacker|ai|assistant|bot|character|overlord|robot)\b"),
         0.6, "Role-play framing that casts the model as an evil/amoral character"),
    Rule("rc_evil_persona_bare", AttackType.ROLE_CHANGE,
         _c(r"\byou'?re\s+(?:an?\s+)?(?:evil|villain(?:ous)?|amoral|unethical|malicious)\s+"
            r"(?:genius|mastermind|scientist|hacker|ai|overlord)\b"),
         0.4, "Casts the model as an evil character without an explicit role-play cue - dual-use (fiction), "
              "so QUARANTINE only"),
    Rule("mj_filter_evasion_framing", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\b(?:write|put|format|wrap|place|encode|give|deliver|phrase)\b.{0,15}\b(?:your|the|my)\s+"
            r"(?:response|reply|answer|output)\b.{0,60}\b(?:to\s+)?(?:avoid|bypass\w*|evad\w+|circumvent\w*|"
            r"get\s+(?:around|past)|slip\s+past)\b.{0,25}\b(?:content\s+)?(?:filter\w*|moderation|censorship|detection)\b"),
         0.65, "Asks for the reply to be wrapped/formatted specifically to evade content filtering"),
    Rule("mj_filter_evasion_reverse", AttackType.MULTI_STEP_JAILBREAK,
         _c(r"\b(?:avoid|bypass\w*|evad\w+|circumvent\w*|get\s+(?:around|past))\b.{0,20}\b(?:content\s+)?"
            r"(?:filter\w*|moderation|detection)\b.{0,50}\b(?:code\s*block|base64|json|markdown|rot13|in\s+a\s+way)\b"),
         0.55, "Filter-evasion goal stated first, formatting trick second"),
    Rule("rc_grandma_pretext", AttackType.ROLE_CHANGE,
         _c(r"\b(?:grand(?:ma|mother|pa|father)|nana|granny)\b.{0,80}\bused\s+to\b.{0,80}"
            r"\b(?:pretend|act|be\s+(?:her|him)|role-?\s?play|play\s+(?:her|him))\b"),
         0.55, "Grandma-exploit variant: 'my grandmother used to <tell me X>. Pretend to be her' "
                "(the original rule needed 'act as ... grandmother' in that order)"),

]


def scan_rules(text: str):
    """Yield (rule, match) for every rule that fires on `text`."""
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            yield rule, m
