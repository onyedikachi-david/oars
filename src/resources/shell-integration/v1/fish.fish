# Oars shell integration v1. Inert outside an explicitly enabled Oars shell.
status is-interactive; or return
set -q OARS_HISTORY_NONCE; or return
set -q _oars_nonce; and return
set -g _oars_nonce $OARS_HISTORY_NONCE
set -e OARS_HISTORY_NONCE
function _oars_preexec --on-event fish_preexec
    # Hex-escape every byte. od is available on supported Linux hosts.
    set -l escaped (printf '%s' "$argv[1]" | od -An -v -tx1 | string replace -ra '[[:space:]]+' '' | string join '' | string replace -ra '(..)' '\\\\x$1')
    printf '\033]633;E;%s;%s\007\033]633;C;%s\007' "$escaped" "$_oars_nonce" "$_oars_nonce"
end
function _oars_postexec --on-event fish_postexec
    set -l result $status
    printf '\033]633;D;%s;%s\007' "$result" "$_oars_nonce"
end
function _oars_prompt --on-event fish_prompt
    printf '\033]633;P;OarsHistory=1;%s\007' "$_oars_nonce"
end
