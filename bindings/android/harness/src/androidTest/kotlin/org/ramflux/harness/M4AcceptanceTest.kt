// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.harness

import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.ramflux.sdk.RamfluxAndroid
import org.ramflux.sdk.RamfluxClient

/**
 * The Android core acceptance, driven by `scripts/run-m4-harness.sh`:
 *
 *     am instrument -e phase first  ...   the process kills itself after the send
 *     am instrument -e phase resume ...   a new process finds everything and continues
 *     am instrument -e phase vault  ...   production refuses to create without hardware
 *
 * One phase runs per instrumentation; the others are skipped.
 */
@RunWith(AndroidJUnit4::class)
class M4AcceptanceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val args = HarnessArgs.from { InstrumentationRegistry.getArguments().getString(it) }
    private val journal = Journal(File(context.noBackupFilesDir, "m4-harness/journal.json"))

    @Test
    fun data_root_is_under_the_no_backup_directory() {
        val root = RamfluxAndroid.dataRoot(context).canonicalFile
        assertTrue(root.startsWith(context.noBackupFilesDir.canonicalFile))
        assertEquals(false, context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP != 0)
    }

    @Test
    fun first_run_creates_an_account_sends_a_dm_and_is_killed() {
        assumeTrue(args.phase == "first" && !args.expectVaultRefusal)
        val client = RamfluxClient.open(RamfluxAndroid.config(context))
        runBlocking { M4Script(client, args, journal).firstRun() }
        // No suspend, no close: the process dies with the stores open and the lock held,
        // which is what a real kill looks like. The driver expects this instrumentation
        // to end with "Process crashed" and then checks the journal.
        Process.killProcess(Process.myPid())
    }

    @Test
    fun resumed_run_finds_the_account_and_the_message_and_sends_again() {
        assumeTrue(args.phase == "resume")
        val client = RamfluxClient.open(RamfluxAndroid.config(context))
        try {
            runBlocking {
                val script = M4Script(client, args, journal)
                script.resumedRun(this)
            }
            assertEquals("true", journal["resumed"])
        } finally {
            client.close()
        }
    }

    @Test
    fun production_build_refuses_account_creation_without_a_hardware_backed_key() {
        assumeTrue(args.phase == "vault" && args.expectVaultRefusal)
        val client = RamfluxClient.open(RamfluxAndroid.config(context))
        try {
            runBlocking { M4Script(client, args, journal).expectVaultRefusal() }
            assertTrue(journal["vault_refusal"] != null)
        } finally {
            client.close()
        }
    }
}
