FROM faust.cs.fau.de:5000/api_deps AS build

FROM python:3.12.2-alpine

WORKDIR /app
COPY ./app /app

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/
COPY --from=build /usr/local/bin /usr/local/bin

#CMD ["python","app.py"]
#CMD ["gunicorn","--config", "gunicorn.py", "app:app"]

