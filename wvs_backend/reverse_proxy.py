from mitmproxy import http
from mitmproxy.tools.main import mitmdump
import os
import sys

class CustomInterceptor:
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Called when a client request is received.
        """
        # Example: Print request URL
        print(f"Request: {flow.request.method} {flow.request.url}")
        
        # Example: Modify headers
        flow.request.headers["Custom-Header"] = "Modified-By-MITM"
        
        # Example: Block certain domains
        if "example.com" in flow.request.pretty_host:
            print(f"Blocking request to {flow.request.pretty_host}")
            flow.response = http.Response.make(
                404,
                b"This domain has been blocked by the proxy",
                {"Content-Type": "text/html"}
            )
    
    def response(self, flow: http.HTTPFlow) -> None:
        """
        Called when a server response is received.
        """
        # Example: Print response status code
        print(f"Response: {flow.response.status_code} for {flow.request.url}")
        
        # Example: Modify response content for HTML pages
        if flow.response.headers.get("content-type", "").startswith("text/html"):
            # Get the original content
            html_content = flow.response.content.decode('utf-8', 'ignore')
            
            # Modify the content (add a marker at the top of the page)
            modified_content = "<div style='background-color: red; color: white; padding: 10px;'>Modified by MITM Proxy!</div>" + html_content
            
            # Update the response with modified content
            flow.response.content = modified_content.encode('utf-8')
            
            # Update content length header
            flow.response.headers["content-length"] = str(len(flow.response.content))

def start_proxy(port=8080):
    """Start the MITM proxy with our custom interceptor"""
    # Arguments to pass to mitmproxy
    args = [
        '-p', str(port),  # Port to listen on
        '-s', __file__,   # Script to use (this file)
        '--set', 'block_global=false',  # Don't block requests to non-local networks
        '--set', 'connection_strategy=eager'  # Connect to the server before client request
    ]
    
    return mitmdump(args)

if __name__ == "__main__":
    # If the script is imported by mitmproxy, it will use the CustomInterceptor class
    # If run directly, it will start the proxy
    if 'mitmproxy' not in sys.modules:
        start_proxy()