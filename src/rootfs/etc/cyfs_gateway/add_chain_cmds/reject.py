import sys

if len(sys.argv) < 2:
    print("Usage: %s <domain>" % sys.argv[0])
    sys.exit(1)

dest = sys.argv[1]
print("call https-sni-probe && eq ${REQ.dest_host} \"%s\" && reject;" % dest)
sys.exit(0)
