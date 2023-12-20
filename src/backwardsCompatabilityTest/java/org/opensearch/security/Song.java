/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.bwc;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.common.Randomness;

public class Song {

    public static final String FIELD_TITLE = "title";
    public static final String FIELD_ARTIST = "artist";
    public static final String FIELD_LYRICS = "lyrics";
    public static final String FIELD_STARS = "stars";
    public static final String FIELD_GENRE = "genre";
    public static final String ARTIST_FIRST = "First artist";
    public static final String ARTIST_STRING = "String";
    public static final String ARTIST_TWINS = "Twins";
    public static final String TITLE_MAGNUM_OPUS = "Magnum Opus";
    public static final String TITLE_SONG_1_PLUS_1 = "Song 1+1";
    public static final String TITLE_NEXT_SONG = "Next song";
    public static final String ARTIST_NO = "No!";
    public static final String TITLE_POISON = "Poison";

    public static final String ARTIST_YES = "yes";

    public static final String TITLE_AFFIRMATIVE = "Affirmative";

    public static final String ARTIST_UNKNOWN = "unknown";
    public static final String TITLE_CONFIDENTIAL = "confidential";

    public static final String LYRICS_1 = "Very deep subject";
    public static final String LYRICS_2 = "Once upon a time";
    public static final String LYRICS_3 = "giant nonsense";
    public static final String LYRICS_4 = "Much too much";
    public static final String LYRICS_5 = "Little to little";
    public static final String LYRICS_6 = "confidential secret classified";

    public static final String GENRE_ROCK = "rock";
    public static final String GENRE_JAZZ = "jazz";
    public static final String GENRE_BLUES = "blues";

    public static final String QUERY_TITLE_NEXT_SONG = FIELD_TITLE + ":" + "\"" + TITLE_NEXT_SONG + "\"";
    public static final String QUERY_TITLE_POISON = FIELD_TITLE + ":" + TITLE_POISON;
    public static final String QUERY_TITLE_MAGNUM_OPUS = FIELD_TITLE + ":" + TITLE_MAGNUM_OPUS;

    public static final Song[] SONGS = {
        new Song(ARTIST_FIRST, TITLE_MAGNUM_OPUS, LYRICS_1, 1, GENRE_ROCK),
        new Song(ARTIST_STRING, TITLE_SONG_1_PLUS_1, LYRICS_2, 2, GENRE_BLUES),
        new Song(ARTIST_TWINS, TITLE_NEXT_SONG, LYRICS_3, 3, GENRE_JAZZ),
        new Song(ARTIST_NO, TITLE_POISON, LYRICS_4, 4, GENRE_ROCK),
        new Song(ARTIST_YES, TITLE_AFFIRMATIVE, LYRICS_5, 5, GENRE_BLUES),
        new Song(ARTIST_UNKNOWN, TITLE_CONFIDENTIAL, LYRICS_6, 6, GENRE_JAZZ) };

    private final String artist;
    private final String title;
    private final String lyrics;
    private final Integer stars;
    private final String genre;

    public Song(String artist, String title, String lyrics, Integer stars, String genre) {
        this.artist = Objects.requireNonNull(artist, "Artist is required");
        this.title = Objects.requireNonNull(title, "Title is required");
        this.lyrics = Objects.requireNonNull(lyrics, "Lyrics is required");
        this.stars = Objects.requireNonNull(stars, "Stars field is required");
        this.genre = Objects.requireNonNull(genre, "Genre field is required");
    }

    public String getArtist() {
        return artist;
    }

    public String getTitle() {
        return title;
    }

    public String getLyrics() {
        return lyrics;
    }

    public Integer getStars() {
        return stars;
    }

    public String getGenre() {
        return genre;
    }

    public Map<String, Object> asMap() {
        return Map.of(FIELD_ARTIST, artist, FIELD_TITLE, title, FIELD_LYRICS, lyrics, FIELD_STARS, stars, FIELD_GENRE, genre);
    }

    public String asJson() throws JsonProcessingException {
        return new ObjectMapper().writeValueAsString(this.asMap());
    }

    public static Song randomSong() {
        return new Song(
            UUID.randomUUID().toString(),
            UUID.randomUUID().toString(),
            UUID.randomUUID().toString(),
            Randomness.get().nextInt(5),
            UUID.randomUUID().toString()
        );
    }
}
