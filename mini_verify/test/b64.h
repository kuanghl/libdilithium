#ifndef __B64_H__
#define __B64_H__

#define BASE64_ENCODE_OUT_SIZE(s) ((unsigned int)((((s) + 2) / 3) * 4 + 1))
#define BASE64_DECODE_OUT_SIZE(s) ((unsigned int)(((s) / 4) * 3))

/**
 * @brief b64Encode - encodes an array of bytes to base64
 * @param[in] in    Input a data buffer for encoding into base64
 * @param[in] inlen The length of input a data buffer
 * @param[out] out  The base64 data buffer for output, 
 *                  that will need to malloc() size = BASE64_ENCODE_OUT_SIZE(inlen) 
 * @return The size of encoded base64 data to output.
 * 
 * @note out is null-terminated encode string.
 * return values is out length, exclusive terminating `\0'
 */
unsigned int
b64Encode(const unsigned char *in, unsigned int inlen, char *out);

/** 
 * @brief b64Decode - decodes an array of bytes from base64
 * @param[in] in    Input a base64 data buffer for decoding into binary
 * @param[in] inlen The length of input a base64 data buffer
 * @param[out] out  The binary data buffer for output.
 *                  that will need to malloc() size = BASE64_DECODE_OUT_SIZE(inlen)
 * @return The size of decoded base64 data to output.
 * 
 * @note return values is out length
 */
unsigned int
b64Decode(const char *in, unsigned int inlen, unsigned char *out);

/* BASE 64 other character */
#define BASE64_PAD '='
#define BASE64DE_FIRST '+'
#define BASE64DE_LAST 'z'

/* BASE 64 encode table */
static const char base64en[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
};

/* ASCII order for BASE 64 decode, 255 in unused character */
static const unsigned char base64de[] = {
	/* nul, soh, stx, etx, eot, enq, ack, bel, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/* can,  em, sub, esc,  fs,  gs,  rs,  us, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/*  sp, '!', '"', '#', '$', '%', '&', ''', */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/* '(', ')', '*', '+', ',', '-', '.', '/', */
	   255, 255, 255,  62, 255, 255, 255,  63,

	/* '0', '1', '2', '3', '4', '5', '6', '7', */
	    52,  53,  54,  55,  56,  57,  58,  59,

	/* '8', '9', ':', ';', '<', '=', '>', '?', */
	    60,  61, 255, 255, 255, 255, 255, 255,

	/* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
	   255,   0,   1,  2,   3,   4,   5,    6,

	/* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
	     7,   8,   9,  10,  11,  12,  13,  14,

	/* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
	    15,  16,  17,  18,  19,  20,  21,  22,

	/* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
	    23,  24,  25, 255, 255, 255, 255, 255,

	/* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
	   255,  26,  27,  28,  29,  30,  31,  32,

	/* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
	    33,  34,  35,  36,  37,  38,  39,  40,

	/* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
	    41,  42,  43,  44,  45,  46,  47,  48,

	/* 'x', 'y', 'z', '{', '|', '}', '~', del, */
	    49,  50,  51, 255, 255, 255, 255, 255
};

unsigned int
b64Encode(const unsigned char *in, unsigned int inlen, char *out)
{
  int s;
  unsigned int i;
  unsigned int j;
  unsigned char c;
  unsigned char l;

  if (!out) {
    // out is NULL return 0
    return 0;
  }

  s = 0;
  l = 0;
  for (i = j = 0; i < inlen; i++) {
    c = in[i];

    // common characters
    switch (s) {
      case 0:
        s = 1;
        out[j++] = base64en[(c >> 2) & 0x3F];
        break;
      case 1:
        s = 2;
        out[j++] = base64en[((l & 0x3) << 4) | ((c >> 4) & 0xF)];
        break;
      case 2:
        s = 0;
        out[j++] = base64en[((l & 0xF) << 2) | ((c >> 6) & 0x3)];
        out[j++] = base64en[c & 0x3F];
        break;
    }
    l = c;
  }

  // other characters
  switch (s) {
    case 1:
      out[j++] = base64en[(l & 0x3) << 4];
      out[j++] = BASE64_PAD;
      out[j++] = BASE64_PAD;
      break;
    case 2:
      out[j++] = base64en[(l & 0xF) << 2];
      out[j++] = BASE64_PAD;
      break;
  }

  out[j] = 0;

  return j;
}

unsigned int
b64Decode(const char *in, unsigned int inlen, unsigned char *out)
{
	unsigned int i;
	unsigned int j;
	unsigned char c;

	if ((inlen & 0x3) || !out) {
		// out is NULL and inlen incorrect
    return 0;
	}

	for (i = j = 0; i < inlen; i++) {
    // other characters
		if (in[i] == BASE64_PAD) {
			break;
		}
		if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST) {
			return 0;
		}

		c = base64de[(unsigned char)in[i]];
		if (c == 255) {
			return 0;
		}

    // common characters
		switch (i & 0x3) {
      case 0:
        out[j] = (c << 2) & 0xFF;
        break;
      case 1:
        out[j++] |= (c >> 4) & 0x3;
        out[j] = (c & 0xF) << 4; 
        break;
      case 2:
        out[j++] |= (c >> 2) & 0xF;
        out[j] = (c & 0x3) << 6;
        break;
      case 3:
        out[j++] |= c;
        break;
		}
	}

	return j;
}

#endif /* B64_H */