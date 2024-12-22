all:
	-gotags -R . > tags
	go build

clean:
	rm -d tags airscan-discover
