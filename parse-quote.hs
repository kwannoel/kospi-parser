{-

DESCRIPTION
Parses PCAP file containing market feed data

-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as P
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import           Data.Foldable              (foldl')
import           Data.Text.Encoding         (decodeUtf8)
import           Data.Text.Read             (decimal)
import           Data.Time                  (TimeOfDay (..), secondsToDiffTime,
                                             secondsToNominalDiffTime,
                                             timeToTimeOfDay,
                                             utcToLocalTimeOfDay)
import           Data.Time.Clock.POSIX      (posixSecondsToUTCTime)
import           Data.Time.LocalTime        (hoursToTimeZone)
import           Network.Pcap
import           System.Environment         (getArgs)

main :: IO ()
main = do
    filePath <- (!! 0) <$> getArgs
    pcapHandle <- openOffline filePath
    _ <- dispatchBS pcapHandle (-1) packetCallback
    return ()

packetCallback :: PktHdr -> ByteString -> IO ()
packetCallback header contents = do
    print packetTime
    case P.parse contentsP contents of
        P.Done _ res -> print res
        _            -> return ()
    Prelude.putStrLn ""
    where
      -- | Packet header times are UNIX-time formatted by default
      --
      --   "time stamps are supplied as seconds since January 1, 1970, 00:00:00 UTC"
      --   A google search yields the result that this is UNIX time.
      --   -- Quoted from pcap docs: https://www.tcpdump.org/manpages/pcap-tstamp.7.html
      --
      --   This tells us how to convert to UTC time from UNIX time:
      --   https://stackoverflow.com/questions/12916353/how-do-i-convert-from-unixtime-to-a-date-time-in-haskell
      packetTime = posixSecondsToUTCTime -- Convert posix time to UTCTime
                 $ secondsToNominalDiffTime -- Convert seconds to posix time
                 $ (realToFrac $ hdrTime header) / 10 ^ 6 -- Convert micro seconds to seconds
      kospiTimeZone = hoursToTimeZone 9 -- GMT +9


-- =========
-- = TYPES =
-- =========

data QuotePacket = QuotePacket
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

-- ===========
-- = PARSERS =
-- ===========

contentsP :: Parser QuotePacket
contentsP = P.choice [ P.try quotePacketP -- Try to parse a quotePacket
                     , P.anyWord8 *> contentsP
                     ]

quotePacketP :: Parser QuotePacket
quotePacketP = do
    P.string "B6034"
    issueCode <- issueIsinP

    skipP 3 -- Issue seq no.
    skipP 2 -- Market Status type

    skipP 7 -- Total bid volume
    bids <- P.count 5 bidP -- bids

    skipP 7 -- Total ask volume
    asks <- P.count 5 askP -- asks

    skipP 5 -- no. of best bid valid quote (total)
    P.count 5 (skipP 4) -- no. of best bid quote (1st - 5th)

    skipP 5 -- no. of best ask valid quote (total)
    P.count 5 (skipP 4) -- no. of best ask quote (1st - 5th)

    acceptTime <- acceptTimeP -- Quote accept time
    P.word8 0xff -- EOF
    return $ QuotePacket { acceptTime, issueCode, bids, asks }

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
