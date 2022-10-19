/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;


class Song {

	static final String FIELD_TITLE = "title";
	static final String FIELD_ARTIST = "artist";
	static final String FIELD_LYRICS = "lyrics";

	static final String FIELD_STARS = "stars";
	static final String ARTIST_FIRST = "First artist";
	static final String ARTIST_STRING = "String";
	static final String ARTIST_TWINS = "Twins";
	static final String TITLE_MAGNUM_OPUS = "Magnum Opus";
	static final String TITLE_SONG_1_PLUS_1 = "Song 1+1";
	static final String TITLE_NEXT_SONG = "Next song";
	static final String ARTIST_NO = "No!";
	static final String TITLE_POISON = "Poison";

	public static final String LYRICS_1 = "Very deep subject";
	public static final String LYRICS_2 = "Once upon a time";
	public static final String LYRICS_3 = "giant nonsense";
	public static final String LYRICS_4 = "Much too much";

	static final String QUERY_TITLE_NEXT_SONG = FIELD_TITLE + ":" + "\"" + TITLE_NEXT_SONG + "\"";
	static final String QUERY_TITLE_POISON = FIELD_TITLE + ":" + TITLE_POISON;
	static final String QUERY_TITLE_MAGNUM_OPUS = FIELD_TITLE + ":" + TITLE_MAGNUM_OPUS;

	static final Object[][] SONGS = {
		{FIELD_ARTIST, ARTIST_FIRST, FIELD_TITLE, TITLE_MAGNUM_OPUS ,FIELD_LYRICS, LYRICS_1, FIELD_STARS, 1},
		{FIELD_ARTIST, ARTIST_STRING, FIELD_TITLE, TITLE_SONG_1_PLUS_1, FIELD_LYRICS, LYRICS_2, FIELD_STARS, 2},
		{FIELD_ARTIST, ARTIST_TWINS, FIELD_TITLE, TITLE_NEXT_SONG, FIELD_LYRICS, LYRICS_3, FIELD_STARS, 3},
		{FIELD_ARTIST, ARTIST_NO, FIELD_TITLE, TITLE_POISON, FIELD_LYRICS, LYRICS_4, FIELD_STARS, 4}
	};
}
