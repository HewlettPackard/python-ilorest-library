python3 -m pip install -r requirements.txt
python3 setup.py sdist --formats=zip
cd dist

python3 -m pip install --upgrade python-ilorest-library-5.3.0.zip
