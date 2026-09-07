# Preserve normal user initialization, then install hooks after prompt plugins.
if [ -r "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi
if [ -r "$HOME/.config/oars/shell/v1/bash.sh" ]; then . "$HOME/.config/oars/shell/v1/bash.sh"; fi
