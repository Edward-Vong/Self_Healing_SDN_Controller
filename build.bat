@echo off
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m compileall src
echo Build complete.