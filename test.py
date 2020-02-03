import jsbeautifier


def is_there_any_assignment(_statement):
    if '=' in _statement:
        return True
    return False

def main():
    parsed_file = jsbeautifier.beautify_file("script.js")
    mySrc = "document.cookie"
    for line in parsed_file.splitlines():
        if mySrc in line:
            if is_there_any_assignment(line):
                if line.lstrip().find("=") < line.lstrip().find(mySrc):
                    print("{}. index in \" {} \"".format(line.lstrip().find(mySrc), line.lstrip()))



if __name__ == '__main__':
    main()