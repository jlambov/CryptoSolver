"""
Database integration for Kryptos analysis tool
Stores analysis results, key attempts, and user sessions
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import sqlalchemy as sa
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

Base = declarative_base()

class AnalysisSession(Base):
    """Store analysis sessions"""
    __tablename__ = 'analysis_sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), unique=True, nullable=False)
    cipher_text = Column(Text, nullable=False)
    cipher_type = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(Text)

class KeyAttempt(Base):
    """Store key attempts and their results"""
    __tablename__ = 'key_attempts'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), nullable=False)
    key_value = Column(String(100), nullable=False)
    key_length = Column(Integer)
    decrypted_text = Column(Text)
    accuracy_score = Column(Float)
    matches = Column(Integer)
    total_known = Column(Integer)
    cipher_method = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    is_successful = Column(Boolean, default=False)
    notes = Column(Text)

class StatisticalAnalysis(Base):
    """Store statistical analysis results"""
    __tablename__ = 'statistical_analysis'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), nullable=False)
    analysis_type = Column(String(50), nullable=False)  # 'frequency', 'ic', 'bigram', etc.
    results = Column(Text)  # JSON string of results
    created_at = Column(DateTime, default=datetime.utcnow)

class KnownPlaintext(Base):
    """Store known plaintext segments"""
    __tablename__ = 'known_plaintext'
    
    id = Column(Integer, primary_key=True)
    cipher_name = Column(String(50), nullable=False)  # 'K4', 'custom', etc.
    position_start = Column(Integer, nullable=False)
    position_end = Column(Integer, nullable=False)
    plaintext = Column(String(100), nullable=False)
    confidence = Column(Float, default=1.0)
    source = Column(String(100))  # 'sanborn', 'user', 'analysis', etc.
    created_at = Column(DateTime, default=datetime.utcnow)

class PatternAnalysis(Base):
    """Store pattern analysis results"""
    __tablename__ = 'pattern_analysis'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), nullable=False)
    pattern_type = Column(String(50), nullable=False)  # 'repeated', 'kasiski', 'word_pattern'
    pattern_data = Column(Text)  # JSON string of pattern data
    significance_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)

class DatabaseManager:
    """Database manager for Kryptos analysis"""
    
    def __init__(self):
        self.database_url = os.getenv('DATABASE_URL')
        if not self.database_url:
            raise ValueError("DATABASE_URL environment variable not set")
        
        # Add connection pool settings for better stability
        self.engine = create_engine(
            self.database_url,
            pool_pre_ping=True,  # Verify connections before use
            pool_recycle=300,    # Recycle connections every 5 minutes
            pool_size=5,         # Maximum number of persistent connections
            max_overflow=10,     # Maximum number of overflow connections
            connect_args={
                "connect_timeout": 10,
                "sslmode": "require"
            }
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Create tables with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                Base.metadata.create_all(bind=self.engine)
                logger.info("Database tables created/verified")
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to create tables after {max_retries} attempts")
                    raise
                logger.warning(f"Attempt {attempt + 1} failed, retrying")
                import time
                time.sleep(1)
    
    def get_session(self):
        """Get database session"""
        return self.SessionLocal()
    
    def create_analysis_session(self, session_id: str, cipher_text: str, cipher_type: str, notes: str = None) -> int:
        """Create a new analysis session"""
        max_retries = 3
        for attempt in range(max_retries):
            db = self.get_session()
            try:
                # Check if session already exists
                existing = db.query(AnalysisSession).filter(
                    AnalysisSession.session_id == session_id
                ).first()
                
                if existing:
                    logger.info(f"Analysis session {session_id} already exists")
                    return existing.id
                
                session = AnalysisSession(
                    session_id=session_id,
                    cipher_text=cipher_text,
                    cipher_type=cipher_type,
                    notes=notes
                )
                db.add(session)
                db.commit()
                db.refresh(session)
                return session.id
            except Exception as e:
                db.rollback()
                if attempt == max_retries - 1:
                    logger.error(f"Error creating analysis session after {max_retries} attempts")
                    raise
                logger.warning(f"Attempt {attempt + 1} failed, retrying")
                import time
                time.sleep(0.5)
            finally:
                db.close()
    
    def save_key_attempt(self, session_id: str, key_value: str, decrypted_text: str, 
                        accuracy_score: float, matches: int, total_known: int,
                        cipher_method: str = None, notes: str = None) -> int:
        """Save a key attempt and its results"""
        max_retries = 3
        for attempt in range(max_retries):
            db = self.get_session()
            try:
                key_attempt = KeyAttempt(
                    session_id=session_id,
                    key_value=key_value,
                    key_length=len(key_value),
                    decrypted_text=decrypted_text,
                    accuracy_score=accuracy_score,
                    matches=matches,
                    total_known=total_known,
                    cipher_method=cipher_method,
                    is_successful=accuracy_score >= 0.8,  # Consider 80%+ as successful
                    notes=notes
                )
                db.add(key_attempt)
                db.commit()
                db.refresh(key_attempt)
                return key_attempt.id
            except Exception as e:
                db.rollback()
                if attempt == max_retries - 1:
                    logger.error(f"Error saving key attempt after {max_retries} attempts")
                    raise
                logger.warning(f"Attempt {attempt + 1} failed, retrying")
                import time
                time.sleep(0.5)
            finally:
                db.close()
    
    def save_statistical_analysis(self, session_id: str, analysis_type: str, results: Dict) -> int:
        """Save statistical analysis results"""
        db = self.get_session()
        try:
            analysis = StatisticalAnalysis(
                session_id=session_id,
                analysis_type=analysis_type,
                results=json.dumps(results)
            )
            db.add(analysis)
            db.commit()
            db.refresh(analysis)
            return analysis.id
        except Exception as e:
            db.rollback()
            logger.error(f"Error saving statistical analysis: {e}")
            raise
        finally:
            db.close()
    
    def save_pattern_analysis(self, session_id: str, pattern_type: str, pattern_data: Dict, 
                            significance_score: float = None) -> int:
        """Save pattern analysis results"""
        db = self.get_session()
        try:
            analysis = PatternAnalysis(
                session_id=session_id,
                pattern_type=pattern_type,
                pattern_data=json.dumps(pattern_data),
                significance_score=significance_score
            )
            db.add(analysis)
            db.commit()
            db.refresh(analysis)
            return analysis.id
        except Exception as e:
            db.rollback()
            logger.error(f"Error saving pattern analysis: {e}")
            raise
        finally:
            db.close()
    
    def get_best_key_attempts(self, session_id: str, limit: int = 10) -> List[Dict]:
        """Get best key attempts for a session"""
        db = self.get_session()
        try:
            attempts = db.query(KeyAttempt).filter(
                KeyAttempt.session_id == session_id
            ).order_by(KeyAttempt.accuracy_score.desc()).limit(limit).all()
            
            results = []
            for attempt in attempts:
                results.append({
                    'id': attempt.id,
                    'key_value': attempt.key_value,
                    'key_length': attempt.key_length,
                    'decrypted_text': attempt.decrypted_text,
                    'accuracy_score': attempt.accuracy_score,
                    'matches': attempt.matches,
                    'total_known': attempt.total_known,
                    'cipher_method': attempt.cipher_method,
                    'is_successful': attempt.is_successful,
                    'created_at': attempt.created_at,
                    'notes': attempt.notes
                })
            return results
        finally:
            db.close()
    
    def get_session_history(self, session_id: str) -> Dict:
        """Get complete history for a session"""
        db = self.get_session()
        try:
            # Get session info
            session = db.query(AnalysisSession).filter(
                AnalysisSession.session_id == session_id
            ).first()
            
            if not session:
                return None
            
            # Get key attempts
            key_attempts = self.get_best_key_attempts(session_id, limit=50)
            
            # Get statistical analyses
            stat_analyses = db.query(StatisticalAnalysis).filter(
                StatisticalAnalysis.session_id == session_id
            ).order_by(StatisticalAnalysis.created_at.desc()).all()
            
            # Get pattern analyses
            pattern_analyses = db.query(PatternAnalysis).filter(
                PatternAnalysis.session_id == session_id
            ).order_by(PatternAnalysis.created_at.desc()).all()
            
            return {
                'session': {
                    'id': session.id,
                    'session_id': session.session_id,
                    'cipher_text': session.cipher_text,
                    'cipher_type': session.cipher_type,
                    'created_at': session.created_at,
                    'updated_at': session.updated_at,
                    'notes': session.notes
                },
                'key_attempts': key_attempts,
                'statistical_analyses': [
                    {
                        'id': sa.id,
                        'analysis_type': sa.analysis_type,
                        'results': json.loads(sa.results),
                        'created_at': sa.created_at
                    } for sa in stat_analyses
                ],
                'pattern_analyses': [
                    {
                        'id': pa.id,
                        'pattern_type': pa.pattern_type,
                        'pattern_data': json.loads(pa.pattern_data),
                        'significance_score': pa.significance_score,
                        'created_at': pa.created_at
                    } for pa in pattern_analyses
                ]
            }
        finally:
            db.close()
    
    def get_known_plaintext(self, cipher_name: str) -> List[Dict]:
        """Get known plaintext segments for a cipher"""
        db = self.get_session()
        try:
            segments = db.query(KnownPlaintext).filter(
                KnownPlaintext.cipher_name == cipher_name
            ).order_by(KnownPlaintext.position_start).all()
            
            return [
                {
                    'id': seg.id,
                    'position_start': seg.position_start,
                    'position_end': seg.position_end,
                    'plaintext': seg.plaintext,
                    'confidence': seg.confidence,
                    'source': seg.source,
                    'created_at': seg.created_at
                } for seg in segments
            ]
        finally:
            db.close()
    
    def add_known_plaintext(self, cipher_name: str, position_start: int, position_end: int,
                          plaintext: str, confidence: float = 1.0, source: str = 'user') -> int:
        """Add a known plaintext segment"""
        db = self.get_session()
        try:
            segment = KnownPlaintext(
                cipher_name=cipher_name,
                position_start=position_start,
                position_end=position_end,
                plaintext=plaintext,
                confidence=confidence,
                source=source
            )
            db.add(segment)
            db.commit()
            db.refresh(segment)
            return segment.id
        except Exception as e:
            db.rollback()
            logger.error(f"Error adding known plaintext: {e}")
            raise
        finally:
            db.close()
    
    def get_analysis_statistics(self) -> Dict:
        """Get overall analysis statistics"""
        db = self.get_session()
        try:
            total_sessions = db.query(AnalysisSession).count()
            total_attempts = db.query(KeyAttempt).count()
            successful_attempts = db.query(KeyAttempt).filter(KeyAttempt.is_successful == True).count()
            
            # Best accuracy score
            best_attempt = db.query(KeyAttempt).order_by(KeyAttempt.accuracy_score.desc()).first()
            
            # Most common cipher types
            cipher_counts = db.query(
                AnalysisSession.cipher_type,
                sa.func.count(AnalysisSession.id).label('count')
            ).group_by(AnalysisSession.cipher_type).all()
            
            return {
                'total_sessions': total_sessions,
                'total_attempts': total_attempts,
                'successful_attempts': successful_attempts,
                'success_rate': successful_attempts / total_attempts if total_attempts > 0 else 0,
                'best_accuracy': best_attempt.accuracy_score if best_attempt else 0,
                'best_key': best_attempt.key_value if best_attempt else None,
                'cipher_type_distribution': {ct: count for ct, count in cipher_counts}
            }
        finally:
            db.close()
    
    def search_similar_keys(self, key_pattern: str, limit: int = 20) -> List[Dict]:
        """Search for similar keys based on pattern"""
        db = self.get_session()
        try:
            # Use SQL LIKE for pattern matching
            attempts = db.query(KeyAttempt).filter(
                KeyAttempt.key_value.like(f'%{key_pattern}%')
            ).order_by(KeyAttempt.accuracy_score.desc()).limit(limit).all()
            
            results = []
            for attempt in attempts:
                results.append({
                    'key_value': attempt.key_value,
                    'accuracy_score': attempt.accuracy_score,
                    'cipher_method': attempt.cipher_method,
                    'created_at': attempt.created_at
                })
            return results
        finally:
            db.close()

def initialize_k4_plaintext(db_manager: DatabaseManager):
    """Initialize K4 known plaintext segments in database"""
    try:
        # Check if K4 segments already exist
        existing = db_manager.get_known_plaintext('K4')
        if existing:
            logger.info("K4 plaintext segments already exist in database")
            return
        
        # Add K4 known segments
        k4_segments = [
            (21, 33, 'EASTNORTHEAST', 'sanborn'),
            (63, 68, 'BERLIN', 'sanborn'),
            (69, 73, 'CLOCK', 'sanborn')
        ]
        
        for start, end, text, source in k4_segments:
            db_manager.add_known_plaintext('K4', start, end, text, 1.0, source)
        
        logger.info("K4 known plaintext segments initialized in database")
        
    except Exception as e:
        logger.error(f"Error initializing K4 plaintext: {e}")