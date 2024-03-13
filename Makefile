cam_flood: cam_flood.c
	gcc -g -Wall cam_flood.c -o cam_flood -lpcap

clean:
	rm -f cam_flood
