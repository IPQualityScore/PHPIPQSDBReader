<?php
namespace IPQualityScore\DB;

class IPNotFoundException extends FileReaderException {
    // Extends FileReaderException to make either catchable with try { } catch(FileReaderException){ }
}