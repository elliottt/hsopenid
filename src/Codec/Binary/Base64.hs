{- |

  Module      :  Codec.Binary.Base64
  Copyright   :  (c) 2006-2008

  Maintainer      : 
  Stability       : unstable
  Portability     : GHC

  Base64 decoding and encoding routines.

  Note:
  This module was taken from the mime package released by Galois, Inc.  The
  original author is unknown.
-}
module Codec.Binary.Base64 
        ( encodeRaw         -- :: Bool -> [Word8] -> String
        , encodeRawString   -- :: Bool -> String -> String
        , encodeRawPrim     -- :: Bool -> Char -> Char -> [Word8] -> String

        , formatOutput      -- :: Int    -> Maybe String -> String -> String

        , decode            -- :: String -> [Word8]
        , decodeToString    -- :: String -> String
        , decodePrim        -- :: Char -> Char -> String -> [Word8]
        ) where

import Data.Bits
import Data.Char
import Data.Word
import Data.Maybe

encodeRawString :: Bool -> String -> String
encodeRawString trail xs = encodeRaw trail (map (fromIntegral.ord) xs)

-- | 'formatOutput n mbLT str' formats 'str', splitting it
-- into lines of length 'n'. The optional value lets you control what
-- line terminator sequence to use; the default is CRLF (as per MIME.)
formatOutput :: Int -> Maybe String -> String -> String
formatOutput n mbTerm str
 | n <= 0    = error ("formatOutput: negative line length " ++ show n)
 | otherwise = chop n str
   where
     crlf :: String
     crlf = fromMaybe "\r\n" mbTerm

     chop _ "" = ""
     chop i xs =
       case splitAt i xs of
         (as,"") -> as
         (as,bs) -> as ++ crlf ++ chop i bs

encodeRaw :: Bool -> [Word8] -> String
encodeRaw trail bs = encodeRawPrim trail '+' '/' bs

-- lets you control what non-alphanum characters to use
-- (The base64url variation uses '*' and '-', for instance.)
-- No support for mapping these to multiple characters in the output though.
encodeRawPrim :: Bool -> Char -> Char -> [Word8] -> String
encodeRawPrim trail ch62 ch63 ls = encoder ls
 where
  trailer xs ys
   | not trail = xs
   | otherwise = xs ++ ys
  f = fromB64 ch62 ch63 
  encoder []    = []
  encoder [x]   = trailer (take 2 (encode3 f x 0 0 "")) "=="
  encoder [x,y] = trailer (take 3 (encode3 f x y 0 "")) "="
  encoder (x:y:z:ws) = encode3 f x y z (encoder ws)

encode3 :: (Word8 -> Char) -> Word8 -> Word8 -> Word8 -> String -> String
encode3 f a b c rs = 
     f (low6 (w24 `shiftR` 18)) :
     f (low6 (w24 `shiftR` 12)) :
     f (low6 (w24 `shiftR` 6))  :
     f (low6 w24) : rs
   where
    w24 :: Word32
    w24 = (fromIntegral a `shiftL` 16) +
          (fromIntegral b `shiftL` 8)  + 
           fromIntegral c

decodeToString :: String -> String
decodeToString str = map (chr.fromIntegral) $ decode str

decode :: String -> [Word8]
decode str = decodePrim '+' '/' str

decodePrim :: Char -> Char -> String -> [Word8]
decodePrim ch62 ch63 str =  decoder $ takeUntilEnd str
 where
  takeUntilEnd "" = []
  takeUntilEnd ('=':_) = []
  takeUntilEnd (x:xs) = 
    case toB64 ch62 ch63 x of
      Nothing -> takeUntilEnd xs
      Just b  -> b : takeUntilEnd xs

decoder :: [Word8] -> [Word8]
decoder [] = []
decoder [x] = take 1 (decode4 x 0 0 0 [])
decoder [x,y] = take 1 (decode4 x y 0 0 []) -- upper 4 bits of second val are known to be 0.
decoder [x,y,z] = take 2 (decode4 x y z 0 [])
decoder (x:y:z:w:xs) = decode4 x y z w (decoder xs)

decode4 :: Word8 -> Word8 -> Word8 -> Word8 -> [Word8] -> [Word8]
decode4 a b c d rs =
  (lowByte (w24 `shiftR` 16)) :
  (lowByte (w24 `shiftR` 8))  :
  (lowByte w24) : rs
 where
  w24 :: Word32
  w24 =
   (fromIntegral a) `shiftL` 18 .|.
   (fromIntegral b) `shiftL` 12 .|.
   (fromIntegral c) `shiftL` 6  .|.
   (fromIntegral d)

toB64 :: Char -> Char -> Char -> Maybe Word8
toB64 a b ch
  | ch >= 'A' && ch <= 'Z' = Just (fromIntegral (ord ch - ord 'A'))
  | ch >= 'a' && ch <= 'z' = Just (26 + fromIntegral (ord ch - ord 'a'))
  | ch >= '0' && ch <= '9' = Just (52 + fromIntegral (ord ch - ord '0'))
  | ch == a = Just 62
  | ch == b = Just 63
  | otherwise = Nothing

fromB64 :: Char -> Char -> Word8 -> Char
fromB64 ch62 ch63 x 
  | x < 26    = chr (ord 'A' + xi)
  | x < 52    = chr (ord 'a' + (xi-26))
  | x < 62    = chr (ord '0' + (xi-52))
  | x == 62   = ch62
  | x == 63   = ch63
  | otherwise = error ("fromB64: index out of range " ++ show x)
 where
  xi :: Int
  xi = fromIntegral x

low6 :: Word32 -> Word8
low6 x = fromIntegral (x .&. 0x3f)

lowByte :: Word32 -> Word8
lowByte x = (fromIntegral x) .&. 0xff

