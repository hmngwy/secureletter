zip:
	mkdir build
	mkdir dist
	cp methods.py build/
	cp -R venv/lib/python3.6/site-packages/* build/
	zip -r dist/secureletter.zip build/*
