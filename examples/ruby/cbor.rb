# Minimal CBOR (RFC 8949) for the subset a Common Access Token uses: integers, byte strings,
# text strings, arrays, maps, tags, and true/false/nil.
#
# Encoding is deterministic (shortest-form integers and lengths, definite lengths only).
# Decoding is strict: it rejects anything an encoder following those rules would not produce,
# plus duplicate map keys and trailing data.
#
# A byte string is a String with binary encoding; a text string is any other String.

module Attribution
  module CBOR
    Tagged = Struct.new(:tag, :value)
    Error = Class.new(StandardError)

    module_function

    def encode(value)
      case value
      when Integer then value >= 0 ? head(0, value) : head(1, -1 - value)
      when String
        value.encoding == Encoding::BINARY ? head(2, value.bytesize) + value : head(3, value.bytesize) + value.b
      when Array then head(4, value.size) + value.map { |item| encode(item) }.join
      when Hash then head(5, value.size) + value.map { |k, v| encode(k) + encode(v) }.join
      when Tagged then head(6, value.tag) + encode(value.value)
      when false then "\xF4".b
      when true then "\xF5".b
      when nil then "\xF6".b
      else raise Error, "cannot encode #{value.class}"
      end
    end

    # Decodes exactly one item and raises if anything follows it.
    def decode(bytes)
      input = StringIO.new(bytes.b)
      value = read(input)
      raise Error, "trailing data" unless input.eof?
      value
    end

    # The initial byte: major type in the top 3 bits, then the argument in its shortest form.
    def head(major, n)
      m = major << 5
      if n < 24 then [m | n].pack("C")
      elsif n < 0x100 then [m | 24, n].pack("CC")
      elsif n < 0x10000 then [m | 25, n].pack("Cn")
      elsif n < 0x100000000 then [m | 26, n].pack("CN")
      else [m | 27, n].pack("CQ>")
      end
    end

    def read(input)
      initial = take(input, 1).ord
      major = initial >> 5
      info = initial & 0x1f

      if major == 7
        return false if info == 20
        return true if info == 21
        return nil if info == 22
        raise Error, "unsupported simple or floating-point value"
      end

      n = argument(input, info)
      case major
      when 0 then n
      when 1 then -1 - n
      when 2 then take(input, n)
      when 3
        text = take(input, n).force_encoding(Encoding::UTF_8)
        raise Error, "invalid UTF-8" unless text.valid_encoding?
        text
      when 4 then Array.new(n) { read(input) }
      when 5
        n.times.each_with_object({}) do |_, map|
          key = read(input)
          raise Error, "unsupported map key" unless key.is_a?(Integer) || key.is_a?(String)
          raise Error, "duplicate map key" if map.key?(key)
          map[key] = read(input)
        end
      else Tagged.new(n, read(input))
      end
    end

    def argument(input, info)
      return info if info < 24
      raise Error, "indefinite or reserved length" if info > 27

      size = 1 << (info - 24)
      n = take(input, size).unpack1({ 1 => "C", 2 => "n", 4 => "N", 8 => "Q>" }.fetch(size))
      raise Error, "integer not in shortest form" if n < [24, 0x100, 0x10000, 0x100000000][info - 24]
      n
    end

    def take(input, n)
      bytes = input.read(n) || "".b
      raise Error, "unexpected end of data" unless bytes.bytesize == n
      bytes
    end
  end
end
