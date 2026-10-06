// SPDX-License-Identifier: MIT
package com.ebremer.lws.notify;

import com.ebremer.lws.Lws;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * An LWS notification envelope: the storage it concerns and one or more Activity Streams activities
 * ({@code Create}, {@code Update}, {@code Delete}, …). A single {@code activity} object is exposed as a
 * one-element list.
 *
 * @param storage the storage the notification is associated with
 * @param activities the activities, in order
 * @param raw the JSON document
 */
public record Notification(URI storage, List<Activity> activities, ObjectNode raw) {
    public Notification {
        activities = List.copyOf(activities);
    }

    /** Parses a notification from UTF-8 JSON bytes. */
    public static Notification parse(byte[] json) {
        return parse(Json.parse(json));
    }

    /** Parses a notification from JSON text. */
    public static Notification parse(String json) {
        return parse(json.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Parses a notification document.
     *
     * @throws LwsProtocolException if it is not a valid notification
     */
    public static Notification parse(JsonNode json) {
        ObjectNode o = Json.requireObject(json, "Notification");
        if (!Lws.hasType(Json.stringOrArray(o.get("type")), Lws.Type.NOTIFICATION)) {
            throw new LwsProtocolException("Document type is not Notification");
        }
        String storageText = Json.text(o, "storage");
        if (storageText == null) throw new LwsProtocolException("Notification has no storage");
        URI storage = Uris.resolveOrNull(null, storageText);
        if (storage == null) throw new LwsProtocolException("Notification storage is not a URI");
        JsonNode act = o.get("activity");
        List<Activity> activities = new ArrayList<>();
        if (act != null && act.isObject()) {
            activities.add(Activity.parse((ObjectNode) act));
        } else if (act != null && act.isArray()) {
            for (JsonNode a : act) activities.add(Activity.parse(Json.requireObject(a, "Activity")));
        } else {
            throw new LwsProtocolException("Notification has no activity");
        }
        return new Notification(storage, activities, o);
    }

    /**
     * An Activity Streams activity describing a change.
     *
     * @param id the activity id
     * @param types the activity types (e.g. {@code Create})
     * @param object the resource concerned
     * @param actor the agent that performed the change
     * @param target the container a resource was added to ({@code Create})
     * @param origin the container a resource was removed from ({@code Delete})
     * @param published when the activity occurred, if parseable
     * @param publishedRaw the {@code published} value as sent
     * @param raw the JSON object
     */
    public record Activity(String id, List<String> types, ActivityObject object, Optional<URI> actor, Optional<URI> target,
                           Optional<URI> origin, Optional<Instant> published, Optional<String> publishedRaw, ObjectNode raw) {
        public Activity {
            types = List.copyOf(types);
        }

        static Activity parse(ObjectNode o) {
            JsonNode obj = o.get("object");
            if (obj == null || !obj.isObject()) throw new LwsProtocolException("Activity has no object");
            String objId = Json.text(obj, "id");
            URI objUri = objId == null ? null : Uris.resolveOrNull(null, objId);
            if (objUri == null) throw new LwsProtocolException("Activity object has no valid id");
            String published = Json.text(o, "published");
            return new Activity(Json.text(o, "id"), Json.stringOrArray(o.get("type")),
                    new ActivityObject(objUri, Json.stringOrArray(obj.get("type")), (ObjectNode) obj),
                    Optional.ofNullable(Json.uri(o, "actor", null)), Optional.ofNullable(Json.uri(o, "target", null)),
                    Optional.ofNullable(Json.uri(o, "origin", null)), Json.instant(published),
                    Optional.ofNullable(published), o);
        }

        /** Whether the activity has {@code type}. */
        public boolean hasType(String type) {
            return types.contains(type) || types.contains("as:" + type)
                    || types.contains("https://www.w3.org/ns/activitystreams#" + type);
        }

        public boolean isCreate() {
            return hasType(Lws.Activity.CREATE);
        }

        public boolean isUpdate() {
            return hasType(Lws.Activity.UPDATE);
        }

        public boolean isDelete() {
            return hasType(Lws.Activity.DELETE);
        }
    }

    /**
     * The resource an activity is about.
     *
     * @param id the resource URI
     * @param types the resource types ({@code Container}, {@code DataResource}, …)
     * @param raw the JSON object
     */
    public record ActivityObject(URI id, List<String> types, ObjectNode raw) {
        public ActivityObject {
            types = List.copyOf(types);
        }

        public boolean isContainer() {
            return Lws.hasType(types, Lws.Type.CONTAINER);
        }

        public boolean isDataResource() {
            return Lws.hasType(types, Lws.Type.DATA_RESOURCE);
        }
    }
}
