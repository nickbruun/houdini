#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "houdini.h"

static const char URL_SAFE[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const char URI_SAFE[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static int
escape(gh_buf *ob, const uint8_t *src, size_t size, int is_url, const char *safe_table)
{
	static const uint8_t hex_chars[] = "0123456789ABCDEF";

	size_t  i = 0, org;
	uint8_t hex_str[3];

	hex_str[0] = '%';

	while (i < size) {
		org = i;
		while (i < size && safe_table[src[i]] != 0)
			i++;

		if (likely(i > org)) {
			if (unlikely(org == 0)) {
				if (i >= size)
					return 0;

				gh_buf_grow(ob, HOUDINI_ESCAPED_SIZE(size));
			}

			gh_buf_put(ob, src + org, i - org);
		}

		/* escaping */
		if (i >= size)
			break;

		if (src[i] == ' ' && is_url) {
			gh_buf_putc(ob, '+');
		} else {
			hex_str[1] = hex_chars[(src[i] >> 4) & 0xF];
			hex_str[2] = hex_chars[src[i] & 0xF];
			gh_buf_put(ob, hex_str, 3);
		}

		i++;
	}

	return 1;
}

int
houdini_escape_uri(gh_buf *ob, const uint8_t *src, size_t size)
{
	return escape(ob, src, size, 0, URI_SAFE);
}

int
houdini_escape_url(gh_buf *ob, const uint8_t *src, size_t size)
{
	return escape(ob, src, size, 1, URL_SAFE);
}

int
houdini_escape_uri_safe_table(gh_buf *ob, const uint8_t *src, size_t size, const char safe_table[256])
{
	return escape(ob, src, size, 0, safe_table);
}

int
houdini_escape_url_safe_table(gh_buf *ob, const uint8_t *src, size_t size, const char safe_table[256])
{
	return escape(ob, src, size, 1, safe_table);
}

static const char* uri_safe_table(const char* base_table, const uint8_t *safe, size_t size)
{
    char *safe_table = malloc(sizeof(char) * 256);
    if (!safe_table)
        return safe_table;

    size_t i = 0;
    while (i < 256)
    {
        safe_table[i] = base_table[i];
        ++i;
    }

    i = 0;
    while (i < size)
    {
        safe_table[safe[i]] = 1;
        ++i;
    }

    return safe_table;
}

const char* houdini_url_safe_table(const uint8_t *safe, size_t size)
{
    return uri_safe_table(URL_SAFE, safe, size);
}

const char* houdini_uri_safe_table(const uint8_t *safe, size_t size)
{
    return uri_safe_table(URI_SAFE, safe, size);
}
