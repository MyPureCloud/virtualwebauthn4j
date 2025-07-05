package com.genesys.virtualwebauthn4j.models;

public record ClientData(String type, String challenge, String origin) {
}
