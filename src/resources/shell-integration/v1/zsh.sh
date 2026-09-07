# Oars shell integration v1. Inert outside an explicitly enabled Oars shell.
[[ -o interactive && -n ${OARS_HISTORY_NONCE:-} && -z ${_oars_nonce:-} ]] || return
_oars_nonce=$OARS_HISTORY_NONCE
unset OARS_HISTORY_NONCE
_oars_running=0
_oars_preexec() {
  emulate -L zsh
  local LC_ALL=C value=$1 byte code escaped='' i
  for ((i=1; i<=${#value}; i++)); do
    byte=${value[i]}
    printf -v code '%d' "'$byte"
    if (( code <= 32 || code == 59 || code == 92 || code == 127 )); then printf -v byte '\\x%02x' "$code"; fi
    escaped+=$byte
  done
  _oars_running=1
  printf '\033]633;E;%s;%s\007\033]633;C;%s\007' "$escaped" "$_oars_nonce" "$_oars_nonce"
}
_oars_precmd() {
  local result=$?
  if (( _oars_running )); then printf '\033]633;D;%s;%s\007' "$result" "$_oars_nonce"; fi
  _oars_running=0
  printf '\033]633;P;OarsHistory=1;%s\007' "$_oars_nonce"
  return "$result"
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec _oars_preexec
add-zsh-hook precmd _oars_precmd
