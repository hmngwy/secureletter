zip:
	mkdir build
	cp methods.py build/
	cp -R venv/lib/python3.6/site-packages/* build/
	cd build
	zip -r secureletter.zip .
