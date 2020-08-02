{-

DESCRIPTION
Parses PCAP file containing market feed data

-}

{-# OPTIONS_GHC -Wall -Wno-unused-do-bind #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as P
import           Data.ByteString            (ByteString)
import qualified Data.ByteString.Char8      as BC (unpack)
import           Data.Foldable              (foldl', traverse_)
import           Data.List                  (sort)
import           Data.Maybe                 (catMaybes)
import           Data.Time                  (TimeOfDay (..), UTCTime,
                                             secondsToNominalDiffTime)
import           Data.Time.Clock.POSIX      (posixSecondsToUTCTime)
import           Network.Pcap
import           System.Environment         (getArgs)

main :: IO ()
main = do
    -- Handle cli arguments
    args <- getArgs
    let (shouldSort, filePath) =
            case args of
                ["-r", fp] -> (True, fp)
                [fp, "-r"] -> (True, fp)
                [fp] -> (False, fp)
                _ -> error "Invalid cli arguments. \n\n\nUSAGE: ./parse-quote [-r] FILE_PATH \n\n\n"

    -- Open the pcap file
    pcapHandle <- openOffline filePath

    -- Get all packets
    rawPkts <- getAllPackets pcapHandle

    if shouldSort
    then
      -- Sort all packets and print them
      traverse_ (putStrLn . formatQuotePacket) (sort $ processPackets $ rawPkts)
    else
      -- Print all quote packets to stdout
      traverse_ (putStrLn . formatQuotePacket) (processPackets $ rawPkts)


-- =========
-- = TYPES =
-- =========

data QuotePacket = QuotePacket
    { packetTime     :: UTCTime
    , packetContents :: PacketContents
    }
    deriving Show

-- | Used to sort packets by accept times
instance Ord QuotePacket where
    q1 <= q2 = time1 <= time2
      where
        time1 = getAcceptTime q1
        time2 = getAcceptTime q2
        getAcceptTime = acceptTime . packetContents

-- | Only checks equality of packet accept times
instance Eq QuotePacket where
    q1 == q2 = time1 == time2
      where
        time1 = getAcceptTime q1
        time2 = getAcceptTime q2
        getAcceptTime = acceptTime . packetContents

data PacketContents = PacketContents
    { acceptTime :: TimeOfDay
    , issueCode  :: IssueCode
    , bids       :: [(Quantity, Price)]
    , asks       :: [(Quantity, Price)]
    }
    deriving Show

type Time = ByteString
type IssueCode = ByteString
type Quantity = Integer
type Price = Integer

-- ==============
-- = FORMATTERS =
-- ==============

formatQuotePacket :: QuotePacket -> String
formatQuotePacket (QuotePacket { packetTime, packetContents }) =
    show packetTime ++ " " ++ formatPacketContents packetContents

formatPacketContents :: PacketContents -> String
formatPacketContents (PacketContents { acceptTime, issueCode, bids, asks }) =
     show acceptTime ++ " "
  ++ BC.unpack issueCode  ++ " "
  ++ formatAll bids ++ " "
  ++ formatAll asks
    where
      formatAll s = unwords $ format <$> s
      format (qty, price) = show qty ++ "@" ++ show price

-- =====================
-- = PACKET PROCESSING =
-- =====================

getAllPackets :: PcapHandle -> IO [(PktHdr, ByteString)]
getAllPackets hdl = do
    res@(hdr, _) <- nextBS hdl
    case hdr of
        -- When no more packets to read, this is returned
        PktHdr 0 0 0 0 -> return []
        _              -> fmap (res :) $ getAllPackets hdl

processPackets :: [(PktHdr, ByteString)] -> [QuotePacket]
processPackets = catMaybes . fmap processPacket

processPacket :: (PktHdr, ByteString) -> Maybe QuotePacket
processPacket (header, contents) = do
    packetContents <- rawPacketContents
    return $ QuotePacket { packetTime, packetContents }
      -- | Packet header times are UNIX-time formatted by default
      --
      --   "time stamps are supplied as seconds since January 1, 1970, 00:00:00 UTC"
      --   A google search yields the result that this is UNIX time.
      --   -- Quoted from pcap docs: https://www.tcpdump.org/manpages/pcap-tstamp.7.html
      --
      --   This tells us how to convert to UTC time from UNIX time:
      --   https://stackoverflow.com/questions/12916353/how-do-i-convert-from-unixtime-to-a-date-time-in-haskell
    where
        rawPacketContents =
            case P.parse contentsP contents of
                P.Done _ res -> Just res
                _            -> Nothing

        packetTime = posixSecondsToUTCTime -- Convert posix time to UTCTime
                $ secondsToNominalDiffTime -- Convert seconds to posix time
                $ (realToFrac $ hdrTime header) / 10 ^ (6 :: Integer) -- Convert micro seconds to seconds


-- ===========
-- = PARSERS =
-- ===========

contentsP :: Parser PacketContents
contentsP = P.choice [ P.try quotePacketP -- Try to parse a quotePacket
                     , P.anyWord8 *> contentsP
                     ]

quotePacketP :: Parser PacketContents
quotePacketP = do
    P.string "B6034"
    issueCode <- issueIsinP

    skipP 3 -- Issue seq no.
    skipP 2 -- Market Status type

    skipP 7 -- Total bid volume
    bids <- reverse <$> P.count 5 bidP -- bids

    skipP 7 -- Total ask volume
    asks <- P.count 5 askP -- asks

    skipP 5 -- no. of best bid valid quote (total)
    P.count 5 (skipP 4) -- no. of best bid quote (1st - 5th)

    skipP 5 -- no. of best ask valid quote (total)
    P.count 5 (skipP 4) -- no. of best ask quote (1st - 5th)

    acceptTime <- acceptTimeP -- Quote accept time
    P.word8 0xff -- EOF
    return $ PacketContents { acceptTime, issueCode, bids, asks }

    where
        skipP n = P.take n -- skip n bytes

        issueIsinP = P.take 12

        acceptTimeP = do
            hh <- numberP 2
            mm <- numberP 2
            ss <- numberP 2
            uu <- numberP 2
            return $ TimeOfDay (fromIntegral hh) (fromIntegral mm) (fromIntegral ss + fromIntegral uu / 100)

        bidP = do
            price <- numberP 5
            qty <- numberP 7
            return (price, qty)

        askP = do
            price <- numberP 5
            qty <- numberP 7
            return (price, qty)

        numberP :: Int -> Parser Integer
        numberP n = do
            digits <- P.count n digitsP
            return $ foldl' (\n1 n2 -> n1 * 10 + n2) 0 digits

        digitsP :: Parser Integer
        digitsP = do
            d <- P.satisfy isDigit
            return $ (toInteger d) `mod` 48
            where
                isDigit byte = byte >= 48 && byte <= 57
