import copy
from pyparsing import *

class Wrap:
    def __init__(self, data):
        self.__data = data
    def unwrap(self):
        return self.__data

class BpParser:
    def __init__(self):
        self.__data = {'variables': {}, 'sections': []}

        name = Word(alphanums + "_")
        comma = Literal(',')
        true = Literal('true').setParseAction(lambda v: Wrap(True))
        false = Literal('false').setParseAction(lambda v: Wrap(False))

        # Variable reference
        varref = Word(alphanums + "_")
        varref.setParseAction(self.varref_action)

        # Boolean literal true/false
        boolean = true | false

        # String
        string = QuotedString('"', escChar='\\').setParseAction(lambda s, l, t: t[0])

        # String concatenation
        stringcat = delimitedList(string|varref, delim='+')
        stringcat.setParseAction(self.stringcat_action)

        # List of strings
        stringlist = Suppress(Literal("[")) + \
            Optional(delimitedList(stringcat)) + \
            Suppress(Optional(comma)) + Literal("]")
        stringlist.setParseAction(self.stringlist_action)

        # Concatenation of strings, strings lists and variables
        element = delimitedList(string|stringlist|varref, delim='+')
        element.setParseAction(self.element_action)

        # Data
        data = boolean | element
        data.setParseAction(lambda s, l, t: t)

        # Element inside a section
        section = Forward()
        dictelem = name + Suppress(Literal(':')|Literal('=')) + (data|section)
        dictelem.setParseAction(self.dictelem_action)

        # Section (unnamed)
        # pylint: disable=expression-not-assigned
        section << Suppress(Literal("{")) + \
            Optional(delimitedList(dictelem)) + \
            Suppress(Optional(comma) + Literal("}"))
        section.setParseAction(self.section_action)
        # pylint: enable=expression-not-assigned

        # Named section
        namedsection = name + section
        namedsection.setParseAction(self.namedsection_action)

        # Variable
        variable = name + Suppress(Literal("=")) + (data|section)
        variable.setParseAction(self.variable_action)

        # Extension
        extension = name + Suppress(Literal("+=")) + data
        extension.setParseAction(self.extension_action)

        # Soong file
        self._grammar = ZeroOrMore(namedsection
                                   | Suppress(variable)
                                   | Suppress(extension)) + StringEnd()
        self._grammar.setParseAction(self.soong_action)

        # C and C++ style comments
        self._grammar.ignore(cppStyleComment | cStyleComment)


    def stringlist_action(self, tokens):
        return [tokens[:-1]]

    def element_action(self, tokens):
        result = copy.deepcopy(tokens[0])
        for token in tokens[1:]:
            if isinstance(token, list):
                result.extend(token)
            else:
                result += token
        return Wrap(result)

    def stringcat_action(self, tokens):
        result = tokens[0]
        for token in tokens[1:]:
            result += token
        return result

    def dictelem_action(self, tokens):
        return (tokens[0], tokens[1].unwrap())

    def section_action(self, tokens):
        result = {}
        for token in tokens:
            result[token[0]] = token[1]
        return Wrap(result)

    def namedsection_action(self, tokens):
        return (tokens[0], tokens[1].unwrap())

    def variable_action(self, tokens):
        var = tokens[0]
        data = tokens[1].unwrap()
        self.variables()[var] = data

    def varref_action(self, tokens):
        varname = tokens[0]
        return [self.variables()[varname]]

    def extension_action(self, tokens):
        varname = tokens[0]
        variables = self.variables()
        value = variables[varname]
        variables[varname] = value + tokens[1].unwrap()

    def soong_action(self, tokens):
        self.__data['sections'].extend(tokens)

    def parse(self, filepath):
        with open(filepath, 'r') as filehandle:
            self._grammar.parseFile(filehandle)

    def data(self):
        return self.__data['sections']

    def variables(self):
        return self.__data['variables']