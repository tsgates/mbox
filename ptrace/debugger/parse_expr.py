import re

# Match a register name: $eax, $gp0, $orig_eax
REGISTER_REGEX = re.compile(r"([a-z]+[a-z0-9_]+)")

# Hexadacimel number (eg. 0xa)
HEXADECIMAL_REGEX = re.compile(r"0x[0-9a-f]+")

# Make sure that the expression does not contain invalid characters
# Examples:
#  (1-2)<<5
#  340&91
EXPR_REGEX = re.compile(r"^[()<>+*/&0-9-]+$")

def replaceHexadecimal(regs):
    """
    Convert an hexadecimal number to decimal number (as string).
    Callback used by parseExpression().
    """
    text = regs.group(0)
    if text.startswith("0x"):
        text = text[2:]
    elif not re.search("[a-f]", text):
        return text
    value = int(text, 16)
    return str(value)

def parseExpression(process, text):
    """
    Parse an expression. Syntax:
     - "10": decimal number
     - "0x10": hexadecimal number
     - "eax": register value
     - "a+b", "a-b", "a*b", "a/b", "a**b", "a<<b", "a>>b": operators

    >>> from ptrace.mockup import FakeProcess
    >>> process = FakeProcess()
    >>> parseExpression(process, "1+1")
    2
    >>> process.setreg("eax", 3)
    >>> parseExpression(process, "eax*0x10")
    48
    """
    # Remove spaces and convert to lower case
    text = text.strip()
    orig_text = text
    if " " in text:
        raise ValueError("Space are forbidden: %r" % text)
    text = text.lower()

    def readRegister(regs):
        name = regs.group(1)
        value = process.getreg(name)
        return str(value)

    # Replace hexadecimal by decimal
    text = HEXADECIMAL_REGEX.sub(replaceHexadecimal, text)

    # Replace registers by their value
    text = REGISTER_REGEX.sub(readRegister, text)

    # Reject invalid characters
    if not EXPR_REGEX.match(text):
        raise ValueError("Invalid expression: %r" % orig_text)

    # Use integer division (a//b) instead of float division (a/b)
    text = text.replace("/", "//")

    # Finally, evaluate the expression
    try:
        value = eval(text)
    except SyntaxError:
        raise ValueError("Invalid expression: %r" % orig_text)
    return value

