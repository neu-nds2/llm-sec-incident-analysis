#!/usr/bin/env python3
"""
Clean Prompt Templates
Simplified, consistent prompts for all LLM providers
"""

from typing import List, Tuple, Dict

class PromptTemplates:
    """
    Clean, consistent prompt templates for security analysis
    """
    
    @staticmethod
    def build_analysis_prompt(question: str, relevant_chunks: List[Tuple], 
                            network_context: str = "", max_length: int = 10000,
                            chunk_preview_length: int = None) -> str:
        """
        Build a clean, universal analysis prompt for all providers
        
        Args:
            question: The security question to analyze
            relevant_chunks: List of (text, score, metadata) tuples
            network_context: Optional network environment context
            max_length: Maximum prompt length
            chunk_preview_length: Maximum length per chunk (None = no truncation, full chunks)
            
        Returns:
            Optimized prompt string
        """
        
        # Clean, universal base prompt
        base_prompt = f"""You are a cybersecurity analyst. Analyze the security data and answer this question:

{question}

Answer with specific evidence (IPs, timestamps, hostnames) or state "Not found in provided data" if insufficient.
Present your analysis and then conclude with EXACTLY two lines, in this order:

FINAL ANSWER = [A, B, C, ...]
CITED CHUNKS = [filename1, filename2, ...]

CITED CHUNKS must list every [filename] block from the Security Data below that
materially supported your FINAL ANSWER. Use the exact filenames shown in
brackets at the start of each chunk (e.g. suricata_alerts_result.json).
Omit chunks you read but did not use. Do not invent filenames.

Network: {network_context}
"""
        
        # Calculate space for security data
        remaining_space = max_length - len(base_prompt) - 100  # 100 char buffer
        
        # Build clean context
        context_parts = []
        current_length = 0
        
        for text, score, meta in relevant_chunks:
            # Clean chunk format - use full chunks unless length specified
            if chunk_preview_length is None:
                # Use complete chunk content (new default)
                chunk_text = PromptTemplates._clean_chunk_text_full(text)
            else:
                # Use truncated chunks (only when explicitly requested)
                chunk_text = PromptTemplates._clean_chunk_text(text, chunk_preview_length)
            
            chunk_entry = f"[{meta['filename']}] {chunk_text}"
            
            if current_length + len(chunk_entry) > remaining_space:
                break
                
            context_parts.append(chunk_entry)
            current_length += len(chunk_entry)
        
        # Combine everything
        final_prompt = base_prompt + "\nSecurity Data:\n" + "\n\n".join(context_parts) + "\n\nAnswer:"
        
        return final_prompt
    
    @staticmethod
    def build_summary_prompt(analysis_results: str, max_length: int = 3000) -> str:
        """
        Build a clean summary prompt
        
        Args:
            analysis_results: Combined analysis results
            max_length: Maximum length of results to include
            
        Returns:
            Summary prompt string
        """
        
        # Truncate results if too long
        if len(analysis_results) > max_length:
            analysis_results = analysis_results[:max_length] + "... [truncated]"
        
        return f"""Summarize this security incident analysis in 3 sentences:

{analysis_results}

Focus on: attack type, key indicators (IPs/hosts), recommended actions.

Summary:"""
    
    @staticmethod
    def _extract_essential_context(network_context: str) -> str:
        """
        Extract only essential network information
        
        Args:
            network_context: Full network context
            
        Returns:
            Essential context only
        """
        essential_info = []
        
        lines = network_context.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Look for essential network info
            if any(keyword in line.lower() for keyword in 
                   ['range:', 'domain:', 'controller:', 'gateway:']):
                # Clean up the line
                if line.startswith('- '):
                    line = line[2:]
                essential_info.append(line)
                
                # Limit to 3-4 most important items
                if len(essential_info) >= 4:
                    break
        
        return '; '.join(essential_info)
    
    @staticmethod
    def _clean_chunk_text_full(text: str) -> str:
        """
        Clean chunk text without truncation (new default)
        
        Args:
            text: Raw chunk text
            
        Returns:
            Cleaned chunk text (complete, no truncation)
        """
        # Remove query metadata prefix if present
        if text.startswith('Query:'):
            lines = text.split('\n')
            # Skip the first line (Query: filename)
            text = '\n'.join(lines[1:]) if len(lines) > 1 else text
        
        # Return complete content (no truncation)
        return text.strip()
    
    @staticmethod
    def _clean_chunk_text(text: str, max_length: int = 300) -> str:
        """
        Clean and truncate chunk text
        
        Args:
            text: Raw chunk text
            max_length: Maximum length (THIS CONTROLS CHUNK SIZE IN PROMPT)
            
        Returns:
            Cleaned chunk text
        """
        # Remove query metadata prefix if present
        if text.startswith('Query:'):
            lines = text.split('\n')
            # Skip the first line (Query: filename)
            text = '\n'.join(lines[1:]) if len(lines) > 1 else text
        
        # Truncate to max length - THIS IS WHERE CHUNKS GET SHORTENED
        if len(text) > max_length:
            text = text[:max_length] + "... [TRUNCATED]"
        
        return text.strip()
    
    @staticmethod
    def get_prompt_stats(prompt: str) -> Dict[str, int]:
        """
        Get statistics about a prompt
        
        Args:
            prompt: The prompt to analyze
            
        Returns:
            Dictionary with prompt statistics
        """
        lines = prompt.split('\n')
        words = prompt.split()
        
        return {
            'total_length': len(prompt),
            'lines': len(lines),
            'words': len(words),
            'estimated_tokens': len(words) * 1.3  # Rough estimate
        }
