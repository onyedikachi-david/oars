# Oars shell integration v1. Inert outside an explicitly enabled Oars shell.
[[ $- == *i* && -n ${OARS_HISTORY_NONCE:-} && -z ${_oars_nonce:-} ]] || return
_oars_nonce=$OARS_HISTORY_NONCE
unset OARS_HISTORY_NONCE
# Do not override the user's history privacy settings or an existing DEBUG hook.
if [[ -n ${HISTCONTROL:-} || -n ${HISTIGNORE:-} || -n $(trap -p DEBUG) || $- == *T* ]] || ! set -o | command grep -Eq '^history[[:space:]]+on$'; then
  printf '\033]633;P;OarsHistory=0;%s\007' "$_oars_nonce"
  return
fi
shopt -s cmdhist lithist
_oars_running=0
_oars_ready=0
_oars_old_prompt=("${PROMPT_COMMAND[@]}")
_oars_escape() {
  local LC_ALL=C value=$1 byte code i
  _oars_escaped=
  for ((i=0; i<${#value}; i++)); do
    byte=${value:i:1}
    printf -v code '%d' "'$byte"
    if (( code <= 32 || code == 59 || code == 92 || code == 127 )); then
      printf -v byte '\\x%02x' "$code"
    fi
    _oars_escaped+=$byte
  done
}
_oars_preexec() {
  [[ $_oars_ready == 1 && $_oars_running == 0 && $BASH_COMMAND != _oars_prompt* ]] || return
  if [[ -n ${HISTCONTROL:-} || -n ${HISTIGNORE:-} || ! -o history || ${HISTSIZE:-500} == 0 ]]; then
    printf '\033]633;P;OarsHistory=0;%s\007' "$_oars_nonce"
    return
  fi
  _oars_running=1
  local line command
  line=$(HISTTIMEFORMAT= builtin history 1; printf '\001')
  line=${line%$'\001'}; line=${line%$'\n'}
  if [[ $line =~ ^[[:blank:]]*[0-9]+[[:blank:]][[:blank:]](.*)$ ]]; then
    command=${BASH_REMATCH[1]}
    _oars_escape "$command"
    printf '\033]633;E;%s;%s\007\033]633;C;%s\007' "$_oars_escaped" "$_oars_nonce" "$_oars_nonce"
  else
    printf '\033]633;P;OarsHistory=0;%s\007' "$_oars_nonce"
  fi
}
_oars_prompt() {
  local result=$? original
  _oars_ready=0
  if [[ $_oars_running == 1 ]]; then printf '\033]633;D;%s;%s\007' "$result" "$_oars_nonce"; fi
  _oars_running=0
  for original in "${_oars_old_prompt[@]}"; do
    # Preserve user-supplied prompt hooks, which already run as shell code.
    [[ -n $original ]] && eval -- "$original"
  done
  if [[ -z ${HISTCONTROL:-} && -z ${HISTIGNORE:-} && -o history && ${HISTSIZE:-500} != 0 ]]; then
    printf '\033]633;P;OarsHistory=1;%s\007' "$_oars_nonce"
  else
    printf '\033]633;P;OarsHistory=0;%s\007' "$_oars_nonce"
  fi
  _oars_ready=1
  return "$result"
}
PROMPT_COMMAND=_oars_prompt
trap '_oars_preexec' DEBUG
