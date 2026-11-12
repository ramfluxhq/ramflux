// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.harness

import java.io.File
import java.io.FileOutputStream
import org.json.JSONObject

/**
 * What the first run reached, written so that a killed process can prove it afterwards.
 *
 * This is the harness's own record, not account data: the point of the acceptance is that
 * the account and the message come back from the core's database, and the journal only
 * tells the second run which identifiers to look for.
 */
class Journal(private val file: File) {
    private var state = if (file.exists()) JSONObject(file.readText()) else JSONObject()

    operator fun get(key: String): String? = if (state.has(key)) state.getString(key) else null

    fun require(key: String): String =
        checkNotNull(get(key)) { "the first run did not record '$key'; did it get that far?" }

    /** Record one fact durably: write a temporary file, fsync it, rename it over the old one. */
    fun put(key: String, value: String) {
        state.put(key, value)
        file.parentFile?.mkdirs()
        val temporary = File(file.parentFile, file.name + ".tmp")
        FileOutputStream(temporary).use { out ->
            out.write(state.toString().toByteArray(Charsets.UTF_8))
            out.fd.sync()
        }
        check(temporary.renameTo(file)) { "could not replace ${file.path}" }
    }

    fun clear() {
        state = JSONObject()
        file.delete()
    }
}
