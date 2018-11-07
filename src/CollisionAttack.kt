import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.io.FileUtils
import java.io.File
import java.util.*
import kotlin.collections.HashMap
import kotlin.collections.HashSet
import kotlin.test.assertEquals


class CollisionAttack {
    private var digest: java.security.MessageDigest = java.security.MessageDigest.getInstance("SHA-1")
    private val r = java.util.Random()

    private fun bytesToHexString(array: ByteArray?): String? {
        if (array == null) return null
        val builder = StringBuilder()
        for (b in array) {
            builder.append(String.format("%02x", b))
        }
        return builder.toString()
    }

    private fun sha1ToBitSet(input: ByteArray, bit_size: Int): BitSet {
        digest.reset()
        digest.update(input)
        val hash = BitSet.valueOf(Arrays.copyOfRange(digest.digest().reversedArray(), 0, bit_size / 8 + 1))
        if (bit_size <= hash.length()) {
            hash.clear(bit_size, hash.length())
        }
        return hash
    }

    private fun testSha1Complete(data1: ByteArray?, data2: ByteArray?) {
        val data1Hashed = DigestUtils.sha1Hex(data1)
        val data2Hashed = DigestUtils.sha1Hex(data2)
        if (Arrays.equals(data1, data2)) {
            assertEquals(data1Hashed, data2Hashed)
        } else {
            throw Error("Sha1 doesn't match!")
        }
    }

    private fun randomBytes(length: Int): ByteArray {
        val random_bytes = ByteArray(length)
        r.nextBytes(random_bytes)
        return random_bytes
    }


    private fun writeBytesToFile(array : ByteArray?, name: String) {
        if (array == null) return
        val file = File(name)
        if (file.exists()) file.delete()
        FileUtils.writeByteArrayToFile(file, array)
    }

    private fun readFile(name : String): String? {
        val file = File(name)
        return bytesToHexString(file.readBytes())

    }


    internal fun collisionAttack(bit_size: Int): Long {
        // Count how many times the hash function is called
        var count: Long = 0
        val hashes: HashMap<BitSet,ByteArray> = HashMap()
        val messages: HashSet<BitSet> =  HashSet()
        var hashCurrent: BitSet
        while(true) {
            count++
            var randomBytes: ByteArray

            do {
                randomBytes = randomBytes(bit_size)
            } while (!messages.add(BitSet.valueOf(randomBytes)))
            // Find the hash of the message
            hashCurrent = sha1ToBitSet(randomBytes, bit_size)
            if (hashes.containsKey(hashCurrent)) {
                println("Collision of hash ${bytesToHexString(hashCurrent.toByteArray())} found after $count iterations")
                //testSha1Complete(hashes[hashCurrent], randomBytes)
                //Print sha1 strings
                writeBytesToFile(hashes[hashCurrent], "file_collisions1-$bit_size")
                writeBytesToFile(randomBytes, "file_collisions2-$bit_size")
                println("Memory Value of file 1: ${bytesToHexString(hashes[hashCurrent])} Disk Value: ${readFile("file_collisions1-$bit_size")}")
                println("Memory Value of file 2: ${bytesToHexString(randomBytes)} Disk Value: ${readFile("file_collisions2-$bit_size")}")
                break
            } else hashes[hashCurrent] = randomBytes
        }
        return count
    }


    fun preImageAttack(bit_size: Int): Long {
        var count: Long = 0
        val messages = HashSet<BitSet>()
        val referenceValue = randomBytes(bit_size)
        var newValue : ByteArray
        val hash0 = sha1ToBitSet(referenceValue, bit_size)
        var hash1: BitSet
        while (true) {
            count++
            do {
                newValue = randomBytes(bit_size)
            } while (!messages.add(BitSet.valueOf(newValue)))
            hash1 = sha1ToBitSet(newValue, bit_size)
            if (hash0 == hash1) break
        }
        //testSha1Complete(hash0.toByteArray(), hash1.toByteArray())
        println("Collision of given hash ${bytesToHexString(hash0.toByteArray())} found after $count iterations")
        println(bytesToHexString(newValue))
        println(bytesToHexString(referenceValue))
        return count
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val ca = CollisionAttack()
            val collision_bytes = 60
            val preimage_bytes = 50
            println("--- Collision attack on $collision_bytes bits ---")
            ca.collisionAttack(collision_bytes)
            println("--- Pre Image attack on $preimage_bytes bits ---")
            ca.preImageAttack(preimage_bytes)
        }
    }
}

