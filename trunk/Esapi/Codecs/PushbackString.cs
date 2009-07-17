using System;

namespace Owasp.Esapi.Codecs
{

    public class PushbackString
    {
        private String input;
        private char? pushback;
        private char? temp;
        private int index = 0;
        private int mark = 0;

        public PushbackString(String input)
        {
            this.input = input;
        }

        public void Pushback(char c)
        {
            pushback = c;
        }
         
        /// <summary>
        /// Get the current index of the PushbackString. Typically used in error messages.
        /// </summary>
        public int Index
        {
            get { return index; }
        }

        public bool HasNext
        {
            get
            {
                if (pushback != null) return true;
                if (input == null) return false;
                if (input.Length == 0) return false;
                if (index >= input.Length) return false;
                return true;
            }
        }

        public char? Next()
        {
            if (pushback != null)
            {
                char? save = pushback;
                pushback = null;
                return save;
            }
            if (input == null) return null;
            if (input.Length == 0) return null;
            if (index >= input.Length) return null;
            return input[index++];
        }

        public char? NextHex()
        {
            char? c = Next();
            if (c == null) return null;
            if (IsHexDigit(c)) return c;
            return null;
        }

        public char? NextOctal()
        {
            char? c = Next();
            if (c == null) return null;
            if (IsOctalDigit(c)) return c;
            return null;
        }

        /// <summary>
        /// Returns true if the parameter character is a hexidecimal digit 0 through 9, a through f, or A through F.  
        /// </summary>
        /// <param name="c"></param>
        /// <returns></returns>
        public static bool IsHexDigit(char? c)
        {
            if (c == null) return false;
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }

        /// <summary>
        /// Returns true if the parameter character is an octal digit 0 through 7.
        /// </summary>
        /// <param name="c"></param>
        /// <returns></returns>
        public static bool IsOctalDigit(char? c)
        {
            if (c == null) return false;
            return c >= '0' && c <= '7';
        }

        /// <summary>
        /// Return the next character without affecting the current index.
        /// </summary>
        /// <returns></returns>
        public char? Peek() {
            if ( pushback != null ) return pushback;
            if ( input == null ) return null;
            if ( input.Length == 0 ) return null;
            if ( index >= input.Length ) return null;
            return input[index];
        }

        /// <summary>
        /// Test to see if the next character is a particular value without affecting the current index.
        /// </summary>
        /// <param name="c"></param>
        /// <returns></returns>
        public bool Peek(char c)
        {
            if (pushback != null && pushback == c) return true;
            if (input == null) return false;
            if (input.Length == 0) return false;
            if (index >= input.Length) return false;
            return input[index] == c;
        }

        public void Mark()
        {
            temp = pushback;
            mark = index;
        }
        public void Reset()
        {
            pushback = temp;
            index = mark;
        }
        protected String Remainder()
        {
            String output = input.Substring(index);
            if (pushback != null)
            {
                output = pushback + output;
            }
            return output;
        }
    }
}
