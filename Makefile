CONTAINER_ID_FILE := container_id.txt

br:
	-docker rm -f $$(cat $(CONTAINER_ID_FILE) 2>/dev/null) || true
	-docker rmi -f dineshr93/ssltool:1.0 || true
	docker build -t dineshr93/ssltool:1.0 .
	docker run -d -p 7860:7860 dineshr93/ssltool:1.0 > $(CONTAINER_ID_FILE)
	docker logs -f $$(cat $(CONTAINER_ID_FILE))

run:
	docker run -d -p 7860:7860 dineshr93/ssltool:1.0 > $(CONTAINER_ID_FILE)
	docker logs -f $$(cat $(CONTAINER_ID_FILE))

rm:
	-docker rm -f $$(cat $(CONTAINER_ID_FILE) 2>/dev/null) || true
	-docker rmi -f dineshr93/ssltool:1.0 || true
	rm -f $(CONTAINER_ID_FILE)

