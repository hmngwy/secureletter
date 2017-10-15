zip:
	mkdir build
	cp methods.py build/
	cp -R venv/lib/python3.6/site-packages/* build/
	cd build
	zip -r secureletter.zip .

deploy:
	aws s3 sync build/secureletter.zip s3://secureletter-app.us-west-2.amazonaws.com
