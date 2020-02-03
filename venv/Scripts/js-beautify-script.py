#!C:\Users\izzty\Documents\GitHub\DOM-Based-XSS-Scanner\venv\Scripts\python.exe
# EASY-INSTALL-ENTRY-SCRIPT: 'jsbeautifier==1.10.3','console_scripts','js-beautify'
__requires__ = 'jsbeautifier==1.10.3'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('jsbeautifier==1.10.3', 'console_scripts', 'js-beautify')()
    )
