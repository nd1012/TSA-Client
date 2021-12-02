namespace wan24.TSAClient
{
    /// <summary>
    /// Arguments helper
    /// </summary>
    internal sealed class Arguments
    {
        /// <summary>
        /// Arguments data
        /// </summary>
        private readonly Dictionary<string, object?> Data = new();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="args">Arguments</param>
        public Arguments(string[] args)
        {
            if (args == null) throw new ArgumentNullException(nameof(args));
            string? last = null, value;// Last key and current value
            string key;// Current key
            for (int i = 0; i < args.Length; i++)
            {
                // Get key/value
                if (args[i].StartsWith("--"))
                {
                    // Key/value pair
                    last = args[i][2..];
                    if (i >= args.Length - 1) throw new InvalidDataException($"Missing value for {last}");
                    key = last;
                    value = args[i + 1];
                    i++;
                }
                else if (args[i].StartsWith("-"))
                {
                    // Flag
                    last = null;
                    key = args[i][1..];
                    value = null;
                }
                else
                {
                    // Multiple values
                    if (last == null) throw new InvalidDataException($"Invalid usage at argument #{i}");
                    key = last;
                    value = args[i];
                }
                // Store parameter value
                if (!Data.ContainsKey(key))
                {
                    // New parameter
                    Data[key] = value;
                }
                else if (Data[key] is List<string> values)
                {
                    // Extend existing value list
                    if (value == null) throw new InvalidDataException($"Mixing up parameter types for {key}");
                    values.Add(value);
                }
                else
                {
                    // Convert existing value to value list
                    Data[key] = new List<string>()
                    {
                        Data[key] as string??throw new InvalidDataException($"Mixing up parameter types for {key}"),
                        value??throw new InvalidDataException($"Mixing up parameter types for {key}")
                    };
                }
            }
        }

        /// <summary>
        /// Get a value
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Value or <see langword="null"/> (if not contained) or an empty string (if the parameter was given as flag)</returns>
        public string? this[string key]
        {
            get
            {
                if (!Data.ContainsKey(key)) return null;
                if (Data[key] == null) return string.Empty;
                return (Data[key] is List<string> values ? values[0] : Data[key]) as string;
            }
        }

        /// <summary>
        /// Count
        /// </summary>
        public int Count => Data.Count;

        /// <summary>
        /// Keys
        /// </summary>
        public IEnumerable<string> Keys => Data.Keys;

        /// <summary>
        /// Determine if a parameter was given
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Given?</returns>
        public bool Contains(string key) => Data.ContainsKey(key);

        /// <summary>
        /// Determine if a flag was given
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Given?</returns>
        public bool HasFlag(string key) => Data.ContainsKey(key) && Data[key] == null;

        /// <summary>
        /// Get values of a parameter
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Values</returns>
        public List<string>? Values(string key) => Data.ContainsKey(key)
            ? Data[key] as List<string> ?? new List<string>() { Data[key] as string ?? throw new InvalidOperationException("Parameter type is flag (has no values)") }
            : null;
    }
}
