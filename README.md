# `wow_srp` for Python

SRP6 library for Python that supports WoW version 1.2 through to 3.3.5.

This is just a Python wrapper [around the original `wow_srp` library](https://github.com/gtker/wow_srp).


## Development

```bash
pip install maturin
curl https://pyenv.run | bash
# For fish
set -U PYENV_ROOT "$HOME/.pyenv"
fish_add_path "$PYENV_ROOT/bin"
pyenv init - | source
pyenv install 3.10
pyenv virtualenv 3.10 pyo3
pyenv activate pyo3
maturin develop
```
