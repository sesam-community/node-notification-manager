FROM python:3

WORKDIR /code
ADD ./requirements.txt /code/requirements.txt
RUN pip install -r requirements.txt

ADD service/* /code/

CMD python app.py